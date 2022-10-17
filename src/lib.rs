use chrono::{DateTime, FixedOffset, NaiveDateTime};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

mod codec;
mod error;
mod generate;
mod jose;
mod nonce;
mod verify;

use ssi::{one_or_many::OneOrMany, vc::VCDateTime};

pub use error::*;
pub use generate::*;
pub use jose::*;
pub use verify::*;

pub trait Metadata {
    fn get_audience(&self) -> &str;
    fn get_credential_types(&self) -> std::slice::Iter<'_, String>;
    fn get_allowed_formats(&self, credential_type: &str) -> std::slice::Iter<'_, CredentialFormat>;
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[non_exhaustive]
pub enum CredentialFormat {
    #[serde(rename = "jwt_vc")]
    JWT,

    #[serde(rename = "ldp_vc")]
    LDP,

    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct PreAuthzCode {
    pub credential_type: OneOrMany<String>,

    #[serde(rename = "exp")]
    pub expires_at: ssi::vc::VCDateTime,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[non_exhaustive]
pub enum TokenType {
    #[serde(rename = "bearer")]
    Bearer,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct TokenResponse {
    pub access_token: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    pub token_type: TokenType,

    pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
#[serde(tag = "proof_type")]
pub enum Proof {
    #[serde(rename = "jwt")]
    JWT { jwt: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct CredentialRequest {
    #[serde(rename = "type")]
    pub credential_type: Option<String>,
    pub format: Option<CredentialFormat>,
    pub proof: Proof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct CredentialResponse {
    pub format: CredentialFormat,
    pub credential: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
#[serde(untagged)]
pub enum Timestamp {
    Numeric(i64),
    VCDateTime(VCDateTime),
}

impl From<i64> for Timestamp {
    fn from(from: i64) -> Self {
        Self::Numeric(from)
    }
}

impl From<VCDateTime> for Timestamp {
    fn from(from: VCDateTime) -> Self {
        Self::VCDateTime(from)
    }
}

impl TryInto<DateTime<FixedOffset>> for Timestamp {
    type Error = ssi::vc::Error;

    fn try_into(self) -> Result<DateTime<FixedOffset>, ssi::vc::Error> {
        match self {
            Self::Numeric(timestamp) => Ok(DateTime::<FixedOffset>::from_utc(
                NaiveDateTime::from_timestamp(timestamp, 0),
                FixedOffset::east(0),
            )),
            Self::VCDateTime(vcdt) => crate::codec::ToDateTime::from_vcdatetime(vcdt),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct ProofOfPossession {
    #[serde(rename = "iss")]
    pub issuer: String,

    #[serde(rename = "aud")]
    pub audience: String,

    #[serde(rename = "iat")]
    pub issued_at: Timestamp,

    #[serde(rename = "exp")]
    pub expires_at: Timestamp,

    #[serde(rename = "jti")]
    pub nonce: String,
}
