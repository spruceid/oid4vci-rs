use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;

pub mod jwe;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponseEncryption {
    jwk: JWK,
    alg: jwe::Algorithm,
    enc: jwe::EncryptionAlgorithm,
}
