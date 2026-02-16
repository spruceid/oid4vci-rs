use serde::{Deserialize, Serialize};
use ssi::jwk::JWK;

pub mod jwe;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponseEncryption {
    pub jwk: JWK,
    pub enc: jwe::EncryptionAlgorithm,
    pub zip: Option<jwe::CompressionAlgorithm>,
}
