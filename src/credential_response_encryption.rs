#![allow(clippy::type_complexity)]
use std::marker::PhantomData;

use openidconnect::{JsonWebKeyType, JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use ssi_jwk::JWK;

pub use crate::types::{BatchCredentialUrl, CredentialUrl, DeferredCredentialUrl, ParUrl};

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponseEncryptionMetadata<JT, JE, JA>
where
    JT: JsonWebKeyType,
    JE: JweContentEncryptionAlgorithm<JT>,
    JA: JweKeyManagementAlgorithm + Clone,
{
    #[serde(bound = "JA: JweKeyManagementAlgorithm")]
    alg_values_supported: Vec<JA>,
    #[serde(bound = "JE: JweContentEncryptionAlgorithm<JT>")]
    enc_values_supported: Vec<JE>,
    encryption_required: bool,
    #[serde(skip)]
    _phantom_jt: PhantomData<JT>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponseEncryption<JT, JE, JA>
where
    JT: JsonWebKeyType,
    JE: JweContentEncryptionAlgorithm<JT>,
    JA: JweKeyManagementAlgorithm + Clone,
{
    jwk: JWK,
    #[serde(bound = "JA: JweKeyManagementAlgorithm")]
    alg: JA,
    #[serde(bound = "JE: JweContentEncryptionAlgorithm<JT>")]
    enc: JE,
    #[serde(skip)]
    _phantom_jt: PhantomData<JT>,
}
