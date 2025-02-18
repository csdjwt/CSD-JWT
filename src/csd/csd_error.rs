// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Alias for a `Result` with the error type [`CsdError`].
pub type CsdResult<T> = Result<T, CsdError>;

#[non_exhaustive]
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
pub enum CsdError {
    #[error("invalid input: {0}")]
    InvalidDisclosure(String),

    #[error("no hasher can be specified for the hashing algorithm {0}")]
    MissingHasher(String),

    #[error("data type is not expected: {0}")]
    DataTypeMismatch(String),

    #[error("claim {0} of disclosure already exists")]
    ClaimCollisionError(String),

    #[error("digest {0} appears multiple times")]
    DuplicateDigestError(String),

    #[error("array disclosure object contains keys other than `...`")]
    InvalidArrayDisclosureObject,

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("invalid input")]
    DeserializationError(String),

    #[error("{0}")]
    Unspecified(String),

    #[error("salt size must be greater than or equal to 16")]
    InvalidSaltSize,

    #[error("the validation ended with {0} unused disclosure(s)")]
    UnusedDisclosures(usize),

    #[error("Error in adding batch of elements in accumulator [{0}]")]
    AddBatch(String),

    #[error("Error in generating batch of witnesses [{0}]")]
    WitnessBatch(String),
}
