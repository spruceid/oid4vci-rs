#![allow(deprecated)]

use chrono::{DateTime, FixedOffset, Utc};
use rocket::form::FromForm;
use serde::{ser::Serializer, Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub use openidconnect;

mod codec;
mod error;
mod generate;
mod jose;
mod nonce;
pub mod proof_of_possession;
pub mod token;
mod verify;

use ssi::{
    one_or_many::OneOrMany,
    vc::{NumericDate, VCDateTime},
};

pub use codec::*;
pub use error::*;
pub use generate::*;
pub use jose::*;
pub use proof_of_possession::*;
pub use verify::*;

pub trait Metadata {
    fn get_audience(&self) -> &str;
    fn get_credential_types(&self) -> std::slice::Iter<'_, String>;
    fn get_allowed_formats(&self, credential_type: &str) -> std::slice::Iter<'_, CredentialFormat>;
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[serde(untagged)]
pub enum MaybeUnknownCredentialFormat {
    Known(CredentialFormat),
    Unknown(String),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[non_exhaustive]
pub enum CredentialFormat {
    #[serde(rename = "jwt_vc")]
    JWT,

    #[serde(rename = "ldp_vc")]
    LDP,
}

impl From<CredentialFormat> for MaybeUnknownCredentialFormat {
    fn from(value: CredentialFormat) -> Self {
        Self::Known(value)
    }
}

impl From<&str> for MaybeUnknownCredentialFormat {
    fn from(value: &str) -> Self {
        serde_json::from_str::<CredentialFormat>(&format!("\"{value}\""))
            .map(Self::Known)
            .unwrap_or_else(|_| Self::Unknown(value.into()))
    }
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshToken {
    pub case_id: String,
    pub app_install_id: String,
    pub ibm_access_token: String,
    pub device_jwk: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[non_exhaustive]
pub enum TokenType {
    #[serde(rename = "bearer")]
    Bearer,
}

#[deprecated = "Use token::Response"]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    pub token_type: TokenType,

    pub expires_in: u64,

    pub authorization_pending: Option<bool>,
}

#[derive(Debug, FromForm, Deserialize, Serialize)]
pub struct TokenQueryParams {
    pub grant_type: String,

    #[field(name = "pre-authorized_code")]
    #[serde(rename = "pre-authorized_code")]
    pub pre_authz_code: String,

    pub pin: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    pub format: Option<MaybeUnknownCredentialFormat>,
    pub proof: Proof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct CredentialResponse {
    pub format: MaybeUnknownCredentialFormat,
    pub credential: Value,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
#[serde(untagged)]
pub enum Timestamp {
    Numeric(NumericDate),
    VCDateTime(VCDateTime),
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value: NumericDate = self.to_owned().into();
        let whole_seconds = value.as_seconds().floor() as i64;
        whole_seconds.serialize(serializer)
    }
}

impl From<Timestamp> for NumericDate {
    fn from(value: Timestamp) -> Self {
        match value {
            Timestamp::Numeric(timestamp) => timestamp,
            Timestamp::VCDateTime(vcdt) => {
                let date_time: DateTime<FixedOffset> = vcdt.into();
                let date_time: DateTime<Utc> = date_time.into();
                date_time.try_into().unwrap()
            }
        }
    }
}

impl From<NumericDate> for Timestamp {
    fn from(from: NumericDate) -> Self {
        Self::Numeric(from)
    }
}

impl From<VCDateTime> for Timestamp {
    fn from(from: VCDateTime) -> Self {
        Self::VCDateTime(from)
    }
}

impl TryInto<DateTime<FixedOffset>> for Timestamp {
    type Error = crate::OIDCError;

    fn try_into(self) -> Result<DateTime<FixedOffset>, crate::OIDCError> {
        match self {
            Self::Numeric(timestamp) => {
                let date_time: DateTime<Utc> = timestamp.into();
                Ok(date_time.into())
            }
            Self::VCDateTime(vcdt) => Ok(crate::codec::ToDateTime::from_vcdatetime(vcdt)?),
        }
    }
}
