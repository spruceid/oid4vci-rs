use std::str::FromStr;

use serde::{Deserialize, Serialize};

mod metadata;

pub use metadata::*;

pub const FORMAT_DC_SD_JWT: &str = "dc+sd-jwt";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DcSdJwtFormat;

impl DcSdJwtFormat {
    pub fn as_str(&self) -> &'static str {
        FORMAT_DC_SD_JWT
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid SD-JWT VC format")]
pub struct InvalidDcSdJwtFormat;

impl FromStr for DcSdJwtFormat {
    type Err = InvalidDcSdJwtFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            FORMAT_DC_SD_JWT => Ok(Self),
            _ => Err(InvalidDcSdJwtFormat),
        }
    }
}

impl Serialize for DcSdJwtFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DcSdJwtFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
