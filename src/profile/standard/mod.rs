use serde::{Deserialize, Serialize};

use crate::{
    authorization::authorization_details::AnyCredentialAuthorizationParams,
    issuer::metadata::{AnyCredentialFormatConfiguration, CredentialFormatMetadata},
    request::AnyCredentialRequestParams,
};

use super::Profile;

pub mod dc_sd_jwt;
pub mod mso_mdoc;
pub mod w3c_vc;

pub use dc_sd_jwt::FORMAT_DC_SD_JWT;
pub use mso_mdoc::FORMAT_MSO_MDOC;
pub use w3c_vc::{W3cVcFormat, FORMAT_JWT_VC_JSON, FORMAT_JWT_VC_JSON_LD, FORMAT_LDP_VC};

/// Profile including all the standard formats.
///
/// This profile implements all the credential formats specified by the OID4VCI
/// specification's [Appendix A].
///
/// [Appendix A]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#appendix-A>
pub struct StandardProfile;

impl Profile for StandardProfile {
    type Format = StandardFormat;
    type FormatMetadata = StandardCredentialFormatMetadata;
    type AuthorizationParams = AnyCredentialAuthorizationParams;
    type RequestParams = AnyCredentialRequestParams;
    type Credential = serde_json::Value;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StandardFormat {
    W3c(W3cVcFormat),
    MsoMdoc,
    DcSdJwt,
    Unknown(String),
}

impl StandardFormat {
    pub fn from_string(s: String) -> Self {
        match s.as_str() {
            FORMAT_JWT_VC_JSON => Self::W3c(W3cVcFormat::JwtVcJson),
            FORMAT_JWT_VC_JSON_LD => Self::W3c(W3cVcFormat::JwtVcJsonLd),
            FORMAT_LDP_VC => Self::W3c(W3cVcFormat::LdpVc),
            FORMAT_MSO_MDOC => Self::MsoMdoc,
            FORMAT_DC_SD_JWT => Self::DcSdJwt,
            _ => Self::Unknown(s),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::W3c(f) => f.as_str(),
            Self::MsoMdoc => FORMAT_MSO_MDOC,
            Self::DcSdJwt => FORMAT_DC_SD_JWT,
            Self::Unknown(f) => f.as_str(),
        }
    }
}

impl Serialize for StandardFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StandardFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from_string)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StandardCredentialFormatMetadata {
    W3c(w3c_vc::W3cVcFormatMetadata),
    MsoMdoc(mso_mdoc::MsoMdocFormatMetadata),
    DcSdJwt(dc_sd_jwt::DcSdJwtFormatMetadata),
    Unknown(AnyCredentialFormatConfiguration),
}

impl CredentialFormatMetadata for StandardCredentialFormatMetadata {
    type Format = StandardFormat;

    type SigningAlgorithm = serde_json::Value;

    fn id(&self) -> StandardFormat {
        match self {
            Self::W3c(f) => StandardFormat::W3c(f.id),
            Self::MsoMdoc(_) => StandardFormat::MsoMdoc,
            Self::DcSdJwt(_) => StandardFormat::DcSdJwt,
            Self::Unknown(other) => StandardFormat::Unknown(other.id.clone()),
        }
    }
}
