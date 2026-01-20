use std::str::FromStr;

use serde::{Deserialize, Serialize};

mod authorization;
mod metadata;
mod request;

pub use authorization::*;
pub use metadata::*;
pub use request::*;

pub const FORMAT_VC_SD_JWT: &str = "vc+sd-jwt";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VcSdJwtFormat;

impl VcSdJwtFormat {
    pub fn as_str(&self) -> &'static str {
        FORMAT_VC_SD_JWT
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid SD-JWT VC format")]
pub struct InvalidVcSdJwtFormat;

impl FromStr for VcSdJwtFormat {
    type Err = InvalidVcSdJwtFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            FORMAT_VC_SD_JWT => Ok(Self),
            _ => Err(InvalidVcSdJwtFormat),
        }
    }
}

impl Serialize for VcSdJwtFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VcSdJwtFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
