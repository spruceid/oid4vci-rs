use std::str::FromStr;

use serde::{Deserialize, Serialize};

mod authorization;
mod metadata;
mod request;
mod response;

pub use authorization::*;
pub use metadata::*;
pub use request::*;
pub use response::*;

pub const FORMAT_MSO_MDOC: &str = "mso_mdoc";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MsoMdocFormat;

impl MsoMdocFormat {
    pub fn as_str(&self) -> &'static str {
        FORMAT_MSO_MDOC
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid ISO mDL format")]
pub struct InvalidMsoMdocFormat;

impl FromStr for MsoMdocFormat {
    type Err = InvalidMsoMdocFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            FORMAT_MSO_MDOC => Ok(Self),
            _ => Err(InvalidMsoMdocFormat),
        }
    }
}

impl Serialize for MsoMdocFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MsoMdocFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
