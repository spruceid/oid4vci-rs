use serde::{Deserialize, Serialize};
use ssi::jwk::JWK;

pub use crate::types::{BatchCredentialUrl, CredentialUrl, DeferredCredentialUrl, ParUrl};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponseEncryptionMetadata {
    alg_values_supported: Vec<Alg>,
    enc_values_supported: Vec<Enc>,
    encryption_required: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponseEncryption {
    jwk: JWK,
    alg: Alg,
    enc: Enc,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Alg {
    #[serde(untagged)]
    Other(String),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Enc {
    #[serde(untagged)]
    Other(String),
}
