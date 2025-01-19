use crate::csd;

use std::fmt::Display;
use std::str::FromStr;
use csd::csd_error::{CsdError, CsdResult};

/// Representation of an SD-JWT of the format
/// `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<optional KB-JWT>`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CsdJwt {
    /// The JWT part.
    pub jwt: String,
    /// The optional key binding JWT.
    pub key_binding_jwt: Option<String>,
}

impl CsdJwt {
    /// Creates a new [`CsdJwt`] from its components.
    pub fn new(jwt: String, key_binding_jwt: Option<String>) -> Self {
        Self {
            jwt,
            key_binding_jwt,
        }
    }

    /// Serializes the components into the final SD-JWT.
    ///
    /// ## Error
    /// Returns [`Error::DeserializationError`] if parsing fails.
    pub fn presentation(&self) -> String {
        let key_bindings = self.key_binding_jwt.as_deref().unwrap_or("");
        format!("{}~{}", self.jwt, key_bindings)
    }

    /// Parses an SD-JWT into its components as [`CsdJwt`].
    pub fn parse(sd_jwt: &str) -> CsdResult<Self> {
        let sd_segments: Vec<&str> = sd_jwt.split('~').collect();
        let num_of_segments = sd_segments.len();
        if num_of_segments < 2 {
            return Err(CsdError::DeserializationError(
                "SD-JWT format is invalid, less than 2 segments".to_string(),
            ));
        }

        let includes_key_binding = sd_jwt.chars().next_back().is_some_and(|char| char != '~');
        if includes_key_binding && num_of_segments < 3 {
            return Err(CsdError::DeserializationError(
                "SD-JWT format is invalid, less than 3 segments with key binding jwt".to_string(),
            ));
        }

        let jwt = sd_segments.first().unwrap().to_string();

        let key_binding = includes_key_binding.then(|| sd_segments[num_of_segments - 1].to_string());

        Ok(Self {
            jwt,
            key_binding_jwt: key_binding,
        })
    }
}

impl Display for CsdJwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&(self.presentation()))
    }
}

impl FromStr for CsdJwt {
    type Err = CsdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}