use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use crate::halo2::RSAError;
use halo2wrong::curves::bn256::Fr;
use halo2wrong::curves::FieldExt;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(crate) struct InputsSerialisationWrapper(pub(crate) Vec<Vec<Fr>>);

pub fn _deserialize_circuit_inputs(
    ser_inputs: HashMap<String, Vec<String>>,
) -> Result<HashMap<String, Vec<Fr>>, RSAError> {
    ser_inputs
        .iter()
        .map(|(k, v)| {
            let fp_vec: Result<Vec<Fr>, RSAError> = v
                .iter()
                .map(|s| {
                    // TODO - support big integers full range, not just u128
                    let int = u128::from_str(s)
                        .map_err(|e| RSAError(format!("Failed to parse input as u128: {}", e)));

                    int.map(|i| Fr::from_u128(i))
                })
                .collect();
            fp_vec.map(|v| (k.clone(), v))
        })
        .collect()
}

impl Serialize for InputsSerialisationWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for vec_fp in &self.0 {
            // Serialize each sub-vector as an array of byte arrays.
            let inner_bytes: Vec<_> = vec_fp
                .iter()
                .map(|fp| fp.to_bytes()) // Convert each element to bytes
                .collect();

            // Serialize this vector of byte arrays as a single element of the outer sequence.
            seq.serialize_element(&inner_bytes)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for InputsSerialisationWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SerializableInputsVisitor;

        impl<'de> Visitor<'de> for SerializableInputsVisitor {
            type Value = InputsSerialisationWrapper;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a sequence of sequences of byte arrays each of length 32")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<InputsSerialisationWrapper, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut outer_vec = Vec::new();
                while let Some(inner_vec_bytes) = seq.next_element::<Vec<[u8; 32]>>()? {
                    let inner_vec = inner_vec_bytes
                        .into_iter()
                        .map(|bytes| Fr::from_bytes(&bytes).expect("Invalid bytes"))
                        .collect();
                    outer_vec.push(inner_vec);
                }
                Ok(InputsSerialisationWrapper(outer_vec))
            }
        }

        deserializer.deserialize_seq(SerializableInputsVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json; // Make sure serde_json is included in your Cargo.toml under [dev-dependencies]

    #[test]
    fn test_serialization() {
        let fr_row1 = vec![Fr::from(1), Fr::from(2)];
        let fr_row2 = vec![Fr::from(3), Fr::from(4)];
        let inputs = InputsSerialisationWrapper(vec![fr_row1, fr_row2]);

        let serialized = serde_json::to_string(&inputs).unwrap();
        println!("Serialized: {}", serialized);

        let deserialized: InputsSerialisationWrapper = serde_json::from_str(&serialized).unwrap();
        for (i, vec) in deserialized.0.iter().enumerate() {
            for (j, fp) in vec.iter().enumerate() {
                assert_eq!(fp, &inputs.0[i][j]);
            }
        }
    }

    #[test]
    fn test_circuit_inputs_deserialization() {
        let mut serialized = HashMap::new();
        serialized.insert("out".to_string(), vec!["1".to_string(), "2".to_string()]);
        let deserialized = _deserialize_circuit_inputs(serialized).unwrap();
        assert_eq!(deserialized.len(), 1);
        assert_eq!(deserialized.get("out").unwrap().len(), 2);
        assert_eq!(deserialized.get("out").unwrap()[0], Fr::from(1));
        assert_eq!(deserialized.get("out").unwrap()[1], Fr::from(2));
    }
}
