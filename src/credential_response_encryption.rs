#![allow(clippy::type_complexity)]

use openidconnect::{JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use ssi_jwk::JWK;

pub use crate::types::{BatchCredentialUrl, CredentialUrl, DeferredCredentialUrl, ParUrl};

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponseEncryptionMetadata<JE, JA>
where
    JE: JweContentEncryptionAlgorithm,
    JA: JweKeyManagementAlgorithm + Clone,
{
    #[serde(bound = "JA: JweKeyManagementAlgorithm")]
    alg_values_supported: Vec<JA>,
    #[serde(bound = "JE: JweContentEncryptionAlgorithm")]
    enc_values_supported: Vec<JE>,
    encryption_required: bool,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponseEncryption<JE, JA>
where
    JE: JweContentEncryptionAlgorithm,
    JA: JweKeyManagementAlgorithm + Clone,
{
    jwk: JWK,
    #[serde(bound = "JA: JweKeyManagementAlgorithm")]
    alg: JA,
    #[serde(bound = "JE: JweContentEncryptionAlgorithm")]
    enc: JE,
}
