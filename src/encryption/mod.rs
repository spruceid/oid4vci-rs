use serde::{Deserialize, Serialize};
use ssi::jwk::JWK;

pub use crate::types::{CredentialUrl, DeferredCredentialUrl, ParUrl};

pub mod jwe;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponseEncryption {
    jwk: JWK,
    alg: jwe::Algorithm,
    enc: jwe::EncryptionAlgorithm,
}
