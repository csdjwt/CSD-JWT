use std::fmt::Display;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use csd::csd_error::CsdError;

use crate::csd;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsdDisclosure {
    /// The claim name, optional for array elements.
    pub claim_name: Option<String>,
    /// The claim Value which can be of any type.
    pub claim_value: Value,
    /// The base64url-encoded string.
    pub disclosure: String,
}

impl CsdDisclosure {
    /// Creates a new instance of [`::Disclosure`].
    ///
    /// Use `.to_string()` to get the actual disclosure.
    pub fn new(claim_name: Option<String>, claim_value: Value) -> Self {
        let input = if let Some(name) = &claim_name {
            format!("[ \"{}\", {}]", &name, &claim_value.to_string())
        } else {
            format!("[{}]", &claim_value.to_string())
        };

        let encoded = multibase::Base::Base64Url.encode(input);
        Self {
            claim_name,
            claim_value,
            disclosure: encoded,
        }
    }

    /// Parses a Base64 encoded disclosure into a [`sd_jwt_payload::Disclosure`].
    ///
    /// ## Error
    ///
    /// Returns an [`Error::InvalidDisclosure`] if input is not a valid disclosure.
    pub fn parse(disclosure: String) -> Result<Self, CsdError> {
        let decoded: Vec<Value> = multibase::Base::Base64Url
            .decode(&disclosure)
            .map_err(|_e| {
                CsdError::InvalidDisclosure(format!(
                    "Base64 decoding of the disclosure was not possible {}",
                    disclosure
                ))
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|_e| {
                    CsdError::InvalidDisclosure(format!(
                        "decoded disclosure could not be serialized as an array {}",
                        disclosure
                    ))
                })
            })?;

        if decoded.len() == 2 {
            Ok(Self {
                claim_name: None,
                claim_value: decoded
                    .get(1)
                    .ok_or(CsdError::InvalidDisclosure("invalid claim name".to_string()))?
                    .clone(),
                disclosure,
            })
        } else if decoded.len() == 3 {
            Ok(Self {
                claim_name: Some(
                    decoded
                        .get(1)
                        .ok_or(CsdError::InvalidDisclosure("invalid claim name".to_string()))?
                        .as_str()
                        .ok_or(CsdError::InvalidDisclosure(
                            "claim name could not be parsed as a string".to_string(),
                        ))?
                        .to_owned(),
                ),
                claim_value: decoded
                    .get(2)
                    .ok_or(CsdError::InvalidDisclosure("invalid claim name".to_string()))?
                    .clone(),
                disclosure,
            })
        } else {
            Err(CsdError::InvalidDisclosure(format!(
                "deserialized array has an invalid length of {}",
                decoded.len()
            )))
        }
    }

    /// Reference the actual disclosure.
    pub fn as_str(&self) -> &str {
        &self.disclosure
    }

    /// Convert this object into the actual disclosure.
    pub fn into_string(self) -> String {
        self.disclosure
    }
}

impl Display for CsdDisclosure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.disclosure)
    }
}