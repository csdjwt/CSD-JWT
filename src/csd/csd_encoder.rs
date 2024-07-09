use std::marker::PhantomData;
use std::str::FromStr;
use ark_ec::pairing::Pairing;
use json_pointer::JsonPointer;
use serde_json::{
    Map,
    Value
};
use vb_accumulator::positive::Accumulator;
use csd::csd_disclosure::CsdDisclosure;
use csd::csd_error::{CsdError, CsdResult};

use crate::{csd, accumulator};
use crate::accumulator::{scalar_from_str, serialize_accumulator, serialize_pk, serialize_witness};

pub(crate) const SD_ALG: &str = "_sd_alg";
pub const HEADER_TYP: &str = "sd-jwt";
pub const ACCUMULATOR_KEY: &str = "accumulator";
pub const PK_KEY: &str = "pk";
pub const PARAM_SEED_KEY: &str = "param_seed";
const DEFAULT_KEY_SEED: u64 = 0u64;
const DEFAULT_PARAM_SEED: u64 = 1u64;


/// Transforms a JSON object into an SD-JWT object by substituting selected values
/// with their corresponding disclosure digests.
pub struct CsdEncoder<'a, C: Pairing> {
    /// The object in JSON format.
    pub(crate) object: Value,
    final_object: Map<String, Value>,
    phantom: PhantomData<&'a C>,
}

impl<C: Pairing> CsdEncoder<'_, C> {
    /// Creates a new [`CsdEncoder`] with `sha-256` hash function.
    ///
    /// ## Error
    /// Returns [`Error::DeserializationError`] if `object` is not a valid JSON object.
    pub fn new(object: &str) -> CsdResult<CsdEncoder<C>> {
        let object: Value = serde_json::from_str(object).map_err(|e| CsdError::DeserializationError(e.to_string()))?;
        if !object.is_object() {
            return Err(CsdError::DataTypeMismatch("expected object".to_owned()));
        }

        Ok(CsdEncoder {
            object,
            final_object: Map::new(),
            phantom: Default::default(),
        })
    }

    /// Creates a new [`CsdEncoder`] with `sha-256` hash function from a serializable object.
    ///
    /// ## Error
    /// Returns [`Error::DeserializationError`] if `object` can not be serialized into a valid JSON object.
    pub fn try_from_serializable<T: serde::Serialize>(object: T) -> std::result::Result<Self, CsdError> {
        let object: Value = serde_json::to_value(&object).map_err(|e| CsdError::DeserializationError(e.to_string()))?;
        CsdEncoder::try_from(object)
    }
}

impl<C: Pairing> TryFrom<Value> for CsdEncoder<'_, C> {
    type Error = CsdError;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if !value.is_object() {
            return Err(CsdError::DataTypeMismatch("expected object".to_owned()));
        }

        Ok(CsdEncoder {
            object: value,
            final_object: Map::new(),
            phantom: Default::default(),
        })
    }
}

impl<C: Pairing> CsdEncoder<'_, C> {
    /// Adds the `_sd_alg` property to the top level of the object.
    /// The value is taken from the [`crate::Hasher::alg_name`] implementation.
    pub fn add_sd_alg_property(&mut self) -> Option<Value> {
        if let Some(object) = self.object.as_object_mut() {
            object.insert(SD_ALG.to_string(), Value::String(String::from(std::any::type_name::<C>())))
        } else {
            None // Should be unreachable since the `self.object` is checked to be an object on creation.
        }
    }

    pub fn conceal(&mut self, path: &str) -> CsdResult<CsdDisclosure> {
        // Determine salt.
        let element_pointer = path
            .parse::<JsonPointer<_, _>>()
            .map_err(|err| CsdError::InvalidPath(format!("{:?}", err)))?;

        let mut parent_pointer = element_pointer.clone();
        let element_key = parent_pointer
            .pop()
            .ok_or(CsdError::InvalidPath("path does not contain any values".to_string()))?;

        let parent = parent_pointer
            .get_mut(&mut self.object)
            .map_err(|err| CsdError::InvalidPath(format!("{:?}", err)))?;

        match parent {
            Value::Object(_) => {
                let parent = parent_pointer
                    .get_mut(&mut self.object)
                    .map_err(|err| CsdError::InvalidPath(format!("{:?}", err)))?
                    .as_object_mut()
                    .ok_or(CsdError::InvalidPath("path does not contain any values".to_string()))?;

                // Remove the value from the parent and create a disclosure for it.
                let disclosure = CsdDisclosure::new(
                    Some(element_key.to_owned()),
                    parent
                        .remove(&element_key)
                        .ok_or(CsdError::InvalidPath(format!("{} does not exist", element_key)))?,
                );

                Ok(disclosure)
            }
            Value::Array(ref mut array) => {
                let index = match usize::from_str(element_key.as_str()) {
                    Ok(index) => index,
                    Err(err) => {
                        return Err(CsdError::Unspecified(format!("Can't convert element key as usize [{err}]")));
                    }
                };
                let element = array.remove(index);
                let disclosure = CsdDisclosure::new(None, element);

                Ok(disclosure)
            }
            _ => Err(CsdError::Unspecified(
                "parent of element can can only be an object or an array".to_string(),
            )),
        }
    }

    /// Returns the modified object as a string.
    pub fn try_to_string(&self) -> CsdResult<String> {
        serde_json::to_string(&self.object)
            .map_err(|_e| CsdError::Unspecified("error while serializing internal object".to_string()))
    }

    /// Returns a reference to the internal object.
    pub fn object(&mut self) -> CsdResult<&Map<String, Value>> {
        // Safety: encoder can be constructed from objects only.

        let (_, keypair, accumulator, mut state) = accumulator::initialize_accumulator::<C>(DEFAULT_KEY_SEED, DEFAULT_PARAM_SEED);

        let mut map = match self.object.as_object() {
            Some(map) => map,
            None => {
                return Err(CsdError::DataTypeMismatch(String::from("encoder initialized with invalid JSON object.")))
            }
        }.to_owned();

        let mut claims: Vec<String> = Vec::new();
        let sd_alg = match map.remove(SD_ALG) {
            Some(sd_alg) => sd_alg,
            None => return Err(CsdError::Unspecified(String::from("No sd-alg field present.")))
        };

        for (key, value) in &map {
            claims.push(format!("{}::{}", key, value.to_string()));
        }

        let scalar_claims: Vec<C::ScalarField> = claims.iter().map(move |x| { scalar_from_str::<C>(x.as_str()) }).collect::<Vec<C::ScalarField>>();

        let accumulator = match accumulator.add_batch(
            scalar_claims.clone(),
            &keypair.secret_key,
            &mut state,
        ) {
            Ok(accumulator) => accumulator,
            Err(err) => return Err(CsdError::AddBatch(format!("{:?}", err)))
        };

        let serialized_accumulator: String = serialize_accumulator(accumulator.clone());
        self.final_object.insert(String::from(ACCUMULATOR_KEY), Value::String(serialized_accumulator));
        // The public key should be retrieved from the did of the issuer
        let serialized_pk: String = serialize_pk(keypair.public_key.clone());
        self.final_object.insert(String::from(PK_KEY), Value::String(serialized_pk));
        self.final_object.insert(String::from(PARAM_SEED_KEY), Value::String(DEFAULT_PARAM_SEED.to_string()));
        self.final_object.insert(String::from(SD_ALG), sd_alg);

        let witnesses = match accumulator.get_membership_witnesses_for_batch(&scalar_claims, &keypair.secret_key, &state) {
            Ok(witnesses) => witnesses,
            Err(err) => return Err(CsdError::WitnessBatch(format!("{:?}", err)))
        };

        for i in 0..claims.len() {
            let claim = match claims.get(i) {
                Some(claim) => claim.to_owned(),
                None => return Err(CsdError::Unspecified(format!("Claim ({i}) not found.")))
            };
            let witness = match witnesses.get(i) {
                Some(witness) => witness.to_owned(),
                None => return Err(CsdError::Unspecified(format!("Witness ({i}) not found.")))
            };
            self.final_object.insert(claim, Value::String(serialize_witness::<C>(witness)));
        }

        Ok(&self.final_object)
    }
}

#[cfg(test)]
mod test {
    use serde::Serialize;
    use serde_json::json;
    use serde_json::Value;

    use crate::Error;

    use super::CsdEncoder;

    #[derive(Serialize)]
    struct TestStruct {
        id: String,
        claim2: Vec<String>,
    }

    fn object() -> Value {
        json!({
      "id": "did:value",
      "claim1": {
        "abc": true
      },
      "claim2": ["arr-value1", "arr-value2"]
    })
    }

    #[test]
    fn simple() {
        let mut encoder = CsdEncoder::try_from(object()).unwrap();
        encoder.conceal("/claim1/abc").unwrap();
        encoder.conceal("/id").unwrap();
        encoder.add_decoys("", 10).unwrap();
        encoder.add_decoys("/claim2", 10).unwrap();
        assert!(encoder.object().unwrap().get("id").is_none());
        assert_eq!(encoder.object.get("_sd").unwrap().as_array().unwrap().len(), 11);
        assert_eq!(encoder.object.get("claim2").unwrap().as_array().unwrap().len(), 12);
    }

    #[test]
    fn errors() {
        let mut encoder = CsdEncoder::try_from(object()).unwrap();
        encoder.conceal("/claim1/abc").unwrap();
        assert!(matches!(
      encoder.conceal("claim2/2").unwrap_err(),
      Error::InvalidPath(_)
    ));
    }

    #[test]
    fn test_wrong_path() {
        let mut encoder = CsdEncoder::try_from(object()).unwrap();
        assert!(matches!(
      encoder.conceal("/claim12").unwrap_err(),
      Error::InvalidPath(_)
    ));
        assert!(matches!(
      encoder.conceal("/claim12/0").unwrap_err(),
      Error::InvalidPath(_)
    ));
    }

    #[test]
    fn test_from_serializable() {
        let test_value = TestStruct {
            id: "did:value".to_string(),
            claim2: vec!["arr-value1".to_string(), "arr-vlaue2".to_string()],
        };
        let mut encoder = CsdEncoder::try_from_serializable(test_value).unwrap();
        encoder.conceal("/id").unwrap();
        encoder.add_decoys("", 10).unwrap();
        encoder.add_decoys("/claim2", 10).unwrap();
        assert!(encoder.object.get("id").is_none());
        assert_eq!(encoder.object.get("_sd").unwrap().as_array().unwrap().len(), 11);
        assert_eq!(encoder.object.get("claim2").unwrap().as_array().unwrap().len(), 12);
    }
}
