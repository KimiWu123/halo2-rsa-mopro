use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::marker::PhantomData;
use std::path::Path;
use halo2_rsa::big_integer::UnassignedInteger;
use halo2_rsa::{RSAPubE, RSAPublicKey, RSASignature};
use halo2wrong::curves::bn256::{Bn256, G1Affine};
use halo2wrong::halo2::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2wrong::halo2::poly::commitment::ParamsProver;
use halo2wrong::halo2::poly::kzg::commitment::KZGCommitmentScheme;
use halo2wrong::halo2::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2wrong::halo2::poly::kzg::strategy::SingleStrategy;
use halo2wrong::halo2::transcript::{Blake2bRead, Blake2bWrite, TranscriptReadBuffer, TranscriptWriterBuffer};
use halo2wrong::utils::decompose_big;
use num_bigint::BigUint;
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use rand::rngs::mock::StepRng;
use rsa::{Hash, PaddingScheme, PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use thiserror::Error;
use crate::halo2::circuit::RSAExample;

pub mod circuit;
pub mod io;
mod serialisation;

#[derive(Debug, Error)]
pub struct RSAError(String);

impl Display for RSAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

type GenerateProofResult = (Vec<u8>, Vec<u8>);

pub fn prove(
    srs_key_path: &str,
    _proving_key_path: &str,
    input: HashMap<String, Vec<String>>,
) -> Result<GenerateProofResult, Box<dyn Error>> {
    use halo2wrong::curves::bn256::Fr as F;
    use sha2::{Digest, Sha256};

    let limb_width = RSAExample::<F>::LIMB_WIDTH;
    let num_limbs = RSAExample::<F>::BITS_LEN / RSAExample::<F>::LIMB_WIDTH;
    // 1. Uniformly sample a RSA key pair.
    let mut rng = StdRng::from_seed([42; 32]);
    let private_key =
        RsaPrivateKey::new(&mut rng, RSAExample::<F>::BITS_LEN).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    // 2. Uniformly sample a message.
    let mut msg: [u8; 128] = [0; 128];
    for i in 0..128 {
        msg[i] = rng.gen();
    }
    // 3. Compute the SHA256 hash of `msg`.
    let hashed_msg = Sha256::digest(&msg);
    // 4. Generate a pkcs1v15 signature.
    let padding = PaddingScheme::PKCS1v15Sign {
        hash: Some(Hash::SHA2_256),
    };
    let mut sign = private_key
        .sign(padding, &hashed_msg)
        .expect("fail to sign a hashed message.");
    sign.reverse();
    let sign_big = BigUint::from_bytes_le(&sign);
    let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
    let signature = RSASignature::new(UnassignedInteger::from(sign_limbs));

    // 5. Construct `RSAPublicKey` from `n` of `public_key` and fixed `e`.
    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
    let n_unassigned = UnassignedInteger::from(n_limbs.clone());
    let e_fix = RSAPubE::Fix(BigUint::from(RSAExample::<F>::DEFAULT_E));
    let public_key = RSAPublicKey::new(n_unassigned, e_fix);

    // 6. Create our circuit!
    let circuit = RSAExample::<F> {
        signature,
        public_key,
        msg: msg.to_vec(),
        _f: PhantomData,
    };

    // 7. Create public inputs
    let n_fes = n_limbs;
    let mut hash_fes = hashed_msg
        .iter()
        .map(|byte| F::from(*byte as u64))
        .collect::<Vec<F>>();
    let mut column0_public_inputs = n_fes;
    column0_public_inputs.append(&mut hash_fes);
    let public_inputs = vec![column0_public_inputs];

    // 8. Generate the proving key
    let srs = io::read_srs_path(Path::new(&srs_key_path));

    let vk = keygen_vk(&srs, &circuit).expect("keygen_vk should not fail");
    let proving_key = keygen_pk(&srs, vk, &circuit).expect("keygen_pk should not fail");

    // 9. Generate a proof.

    // Check if the circuit should only generate the Proving Key and not the proof
    let toggle = input.get("gen_only").map(|v| v[0].parse::<bool>().unwrap()).unwrap_or(false);

    if toggle {
        return Ok((vec![], vec![]));
    }

    let sliced_pub_inputs: Vec<&[F]> = public_inputs.iter().map(|inner_vec| inner_vec.as_slice()).collect();
    let sliced_pub_inputs: &[&[&[F]]] = &vec![sliced_pub_inputs.as_slice()];

    let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());


    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, Blake2bWrite<_, _, _>, _>(
        &srs,
        &proving_key,
        &[circuit],
        sliced_pub_inputs,
        StepRng::new(0, 0),
        &mut transcript,
    )
        .map_err(|_| RSAError("Failed to create the proof".to_string()))?;

    let proof = transcript.finalize();

    // 10. Serialize the public inputs.
    let serialized_inputs = bincode::serialize(&serialisation::InputsSerialisationWrapper(public_inputs))
        .map_err(|e| RSAError(format!("Serialisation of Inputs failed: {}", e)))?;

    Ok((proof, serialized_inputs))
}

pub fn verify(
    srs_key_path: &str,
    _verifying_key_path: &str,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    use halo2wrong::curves::bn256::Fr as F;
    use sha2::{Digest, Sha256};

    let limb_width = RSAExample::<F>::LIMB_WIDTH;
    let num_limbs = RSAExample::<F>::BITS_LEN / RSAExample::<F>::LIMB_WIDTH;
    // 1. Uniformly sample a RSA key pair.
    let mut rng = StdRng::from_seed([42; 32]);
    let private_key =
        RsaPrivateKey::new(&mut rng, RSAExample::<F>::BITS_LEN).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    // 2. Uniformly sample a message.
    let mut msg: [u8; 128] = [0; 128];
    for i in 0..128 {
        msg[i] = rng.gen();
    }
    // 3. Compute the SHA256 hash of `msg`.
    let hashed_msg = Sha256::digest(&msg);
    // 4. Generate a pkcs1v15 signature.
    let padding = PaddingScheme::PKCS1v15Sign {
        hash: Some(Hash::SHA2_256),
    };
    let mut sign = private_key
        .sign(padding, &hashed_msg)
        .expect("fail to sign a hashed message.");
    sign.reverse();
    let sign_big = BigUint::from_bytes_le(&sign);
    let sign_limbs = decompose_big::<F>(sign_big.clone(), num_limbs, limb_width);
    let signature = RSASignature::new(UnassignedInteger::from(sign_limbs));

    // 5. Construct `RSAPublicKey` from `n` of `public_key` and fixed `e`.
    let n_big = BigUint::from_radix_le(&public_key.n().clone().to_radix_le(16), 16).unwrap();
    let n_limbs = decompose_big::<F>(n_big.clone(), num_limbs, limb_width);
    let n_unassigned = UnassignedInteger::from(n_limbs.clone());
    let e_fix = RSAPubE::Fix(BigUint::from(RSAExample::<F>::DEFAULT_E));
    let public_key = RSAPublicKey::new(n_unassigned, e_fix);

    // 6. Create our circuit!
    let circuit = RSAExample::<F> {
        signature,
        public_key,
        msg: msg.to_vec(),
        _f: PhantomData,
    };

    // 7. Generate the proving key
    let srs = io::read_srs_path(Path::new(&srs_key_path));

    let vk = keygen_vk(&srs, &circuit).expect("keygen_vk should not fail");

    // 8. Deserialize the public inputs.

    let deserialized_inputs: Vec<Vec<F>> = bincode::deserialize::<serialisation::InputsSerialisationWrapper>(&public_inputs)
        .map_err(|e| RSAError(e.to_string()))?.0;

    // 9. Verify the proof.
    let sliced_pub_inputs: Vec<&[F]> = deserialized_inputs.iter().map(|inner_vec| inner_vec.as_slice()).collect();
    let sliced_pub_inputs: &[&[&[F]]] = &vec![sliced_pub_inputs.as_slice()];

    let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
    verify_proof::<_, VerifierGWC<_>, _, Blake2bRead<_, _, _>, _>(
        srs.verifier_params(),
        &vk,
        SingleStrategy::new(&srs),
        sliced_pub_inputs,
        &mut transcript,
    )
        .map_err(|_| RSAError("Failed to verify the proof".to_string()))?;

    Ok(true)
}
