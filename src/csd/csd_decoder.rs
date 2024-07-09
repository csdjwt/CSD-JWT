use std::{str::FromStr, marker::PhantomData, thread};
use std::thread::JoinHandle;
use ark_ec::pairing::Pairing;
use serde_json::Map;
use serde_json::Value;
use vb_accumulator::positive::{Accumulator};
use csd::csd_error::CsdError;

use crate::csd;
use csd::csd_encoder::{ACCUMULATOR_KEY, PARAM_SEED_KEY, PK_KEY, SD_ALG};
use crate::accumulator::{deserialize_accumulator, deserialize_pk, deserialize_witness, generate_params, scalar_from_str};

/// Substitutes digests in an SD-JWT object by their corresponding plain text values provided by disclosures.
pub struct CsdDecoder<'a, C: Pairing> {
    phantom: PhantomData<&'a C>,
}

impl<C: Pairing> CsdDecoder<'_, C> {
    /// Creates a new [`CsdDecoder`] without any hashers.
    pub fn new() -> Self {
        CsdDecoder::<C> { phantom: Default::default() }
    }

    /// Decodes an SD-JWT `object` containing by Substituting the digests with their corresponding
    /// plain text values provided by `disclosures`.
    pub fn decode(
        &self,
        object: &Map<String, Value>,
    ) -> Result<Map<String, Value>, CsdError> {
        // Decode the object recursively.
        self.decode_object(object)
    }

    fn decode_object(
        &self,
        object: &Map<String, Value>,
    ) -> Result<Map<String, Value>, CsdError> {
        let mut output: Map<String, Value> = object.clone();
        for (key, value) in object.iter() {
            match value {
                Value::Object(object) => {
                    let decoded_object = self.decode_object(object)?;
                    if !decoded_object.is_empty() {
                        output.insert(key.to_string(), Value::Object(decoded_object));
                    }
                }
                Value::Array(_) => {
                    return Err(CsdError::Unspecified(String::from("No arrays allowed yet!")))
                }
                // Only objects and arrays require decoding.
                _ => {}
            }
        }
        Ok(output)
    }

    pub(crate) fn validate_object(&self, mut object: Map<String, Value>) -> Result<bool, CsdError> {
        let (_, accumulator) = match object.get_key_value(ACCUMULATOR_KEY) {
            Some(result) => result,
            None => return Err(CsdError::Unspecified(String::from("No accumulator found!")))
        };
        let accumulator = match accumulator {
            Value::String(val) => val.to_owned(),
            _ => return Err(CsdError::Unspecified(String::from("Accumulator value found is not a string!")))
        };
        object.remove(ACCUMULATOR_KEY);

        let (_, params_seed) = match object.get_key_value(PARAM_SEED_KEY) {
            Some(result) => result,
            None => return Err(CsdError::Unspecified(String::from("No param seed found!")))
        };
        let params_seed = match params_seed {
            Value::String(val) => u64::from_str(val.as_str()),
            _ => return Err(CsdError::Unspecified(String::from("Param seed value found is not a string!")))
        };
        let params_seed = match params_seed {
            Ok(params_seed) => params_seed,
            Err(err) => return Err(CsdError::Unspecified(String::from(format!("Param seed value is a string but can't be converted to u64! {:?}", err))))
        };
        let params = generate_params::<C>(params_seed);
        object.remove(PARAM_SEED_KEY);

        let (_, pk) = match object.get_key_value(PK_KEY) {
            Some(result) => result,
            None => return Err(CsdError::Unspecified(String::from("No public key found!")))
        };
        let pk = match pk {
            Value::String(val) => val.to_owned(),
            _ => return Err(CsdError::Unspecified(String::from("Public key value found is not a string!")))
        };
        let pk = deserialize_pk::<C>(pk);
        object.remove(PK_KEY);

        let (_, _) = match object.get_key_value(SD_ALG) {
            Some(result) => result,
            None => return Err(CsdError::Unspecified(String::from("No Selective Disclosure algorithm found!")))
        };
        object.remove(SD_ALG);

        let accumulator= deserialize_accumulator::<C>(accumulator);
        let mut results:  Vec<JoinHandle<bool>> = vec![];
        let mut i: usize = 0;
        for (key, value) in object {
            let thread_acc = accumulator.clone();
            let element = scalar_from_str::<C>(key.clone().as_str());
            let witness = deserialize_witness::<C>(match value {
                Value::String(val) => val.to_owned(),
                _ => return Err(CsdError::Unspecified(String::from(format!("Witness [{:?}] not a string", value))))
            });
            let thread_pk = pk.clone();
            let thread_params = params.clone();

            results.insert(i, thread::spawn(move || { thread_acc.verify_membership(&element, &witness, &thread_pk, &thread_params) }));
            i += 1;
            // println!("Key {} verified!", key);
        }

        for result in results {
            assert!(result.join().unwrap());
        }

        Ok(true)
    }
}
