use serde::{Deserialize, Serialize};
use ssi::claims::jws::JwsBuf;

pub mod jwt;

pub type ProofSigningAlgValuesSupported = Vec<ssi::jwk::Algorithm>;

/// Proofs.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub enum Proofs {
    /// JWT proofs.
    #[serde(rename = "jwt")]
    Jwt(Vec<JwsBuf>),

    /// Data Integrity proofs.
    #[serde(rename = "di_vp")]
    DiVp(Vec<serde_json::Value>),

    /// Attestation.
    #[serde(rename = "attestation")]
    Attestation(Attestation),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Attestation(pub String);

impl Serialize for Attestation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        [&self.0].serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Attestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let [jwt] = <[String; 1]>::deserialize(deserializer)?;
        Ok(Attestation(jwt))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum VerificationError {
    /// Verification failed.
    ///
    /// Something went wrong before the signature or claims could be verified.
    #[error(transparent)]
    Failed(#[from] ssi::claims::ProofValidationError),

    /// Invalid signature or claims.
    #[error(transparent)]
    Invalid(#[from] ssi::claims::Invalid),
}
