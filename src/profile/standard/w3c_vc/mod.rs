use std::str::FromStr;

use serde::{Deserialize, Serialize};

mod metadata;
mod response;

pub use metadata::*;

pub const FORMAT_JWT_VC_JSON: &str = "jwt_vc_json";
pub const FORMAT_JWT_VC_JSON_LD: &str = "jwt_vc_json-ld";
pub const FORMAT_LDP_VC: &str = "ldp_vc";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum W3cVcFormat {
    JwtVcJson,
    JwtVcJsonLd,
    LdpVc,
}

impl W3cVcFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::JwtVcJson => FORMAT_JWT_VC_JSON,
            Self::JwtVcJsonLd => FORMAT_JWT_VC_JSON_LD,
            Self::LdpVc => FORMAT_LDP_VC,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid W3C VC format")]
pub struct InvalidW3cVcFormat;

impl FromStr for W3cVcFormat {
    type Err = InvalidW3cVcFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            FORMAT_JWT_VC_JSON => Ok(Self::JwtVcJson),
            FORMAT_JWT_VC_JSON_LD => Ok(Self::JwtVcJsonLd),
            FORMAT_LDP_VC => Ok(Self::LdpVc),
            _ => Err(InvalidW3cVcFormat),
        }
    }
}

impl Serialize for W3cVcFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for W3cVcFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
