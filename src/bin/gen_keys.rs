use std::env;
use std::path::Path;

use halo2wrong::curves::bn256::Bn256;
use halo2wrong::halo2::poly::commitment::ParamsProver;
use halo2wrong::halo2::poly::kzg::commitment::ParamsKZG;
use mopro_bindings::io::write_srs;

pub fn main() {
    // Get the project's root directory from the `CARGO_MANIFEST_DIR` environment variable
    let project_root = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");

    // Create the path to the `out` directory under the project's root directory
    let out_dir = Path::new(&project_root).join("out");

    // Check if the `out` directory exists, if not, create it
    if !out_dir.exists() {
        std::fs::create_dir(&out_dir).expect("Unable to create out directory");
    }

    // Set up the circuit
    let k = 18;
    println!("Generating SRS for RSA circuit with k = {}", k);

    // Generate SRS
    let srs = ParamsKZG::<Bn256>::new(k);

    let srs_path = out_dir.join("rsa_srs");
    write_srs(&srs, srs_path.as_path());

    println!("Preparation finished successfully.");
    println!("SRS stored in {}", srs_path.display());
}