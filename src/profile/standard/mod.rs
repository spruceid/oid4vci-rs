use serde::{Deserialize, Serialize};

use crate::{
    authorization::CredentialAuthorizationParams,
    issuer::metadata::{AnyCredentialFormatConfiguration, CredentialFormatMetadata},
    request::CredentialRequestParams,
};

use super::Profile;

pub mod mso_mdoc;
pub mod vc_sd_jwt;
pub mod w3c_vc;

pub use mso_mdoc::FORMAT_MSO_MDOC;
pub use vc_sd_jwt::FORMAT_VC_SD_JWT;
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
    type FormatConfiguration = StandardCredentialFormatMetadata;
    type AuthorizationParams = StandardCredentialAuthorizationParams;
    type RequestParams = StandardCredentialRequestParams;
    type Credential = serde_json::Value;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StandardFormat {
    W3c(W3cVcFormat),
    MsoMdoc,
    VcSdJwt,
    Unknown(String),
}

impl StandardFormat {
    pub fn from_string(s: String) -> Self {
        match s.as_str() {
            FORMAT_JWT_VC_JSON => Self::W3c(W3cVcFormat::JwtVcJson),
            FORMAT_JWT_VC_JSON_LD => Self::W3c(W3cVcFormat::JwtVcJsonLd),
            FORMAT_LDP_VC => Self::W3c(W3cVcFormat::LdpVc),
            FORMAT_MSO_MDOC => Self::MsoMdoc,
            FORMAT_VC_SD_JWT => Self::VcSdJwt,
            _ => Self::Unknown(s),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::W3c(f) => f.as_str(),
            Self::MsoMdoc => FORMAT_MSO_MDOC,
            Self::VcSdJwt => FORMAT_VC_SD_JWT,
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
    VcSdJwt(vc_sd_jwt::VcSdJwtFormatMetadata),
    Unknown(AnyCredentialFormatConfiguration),
}

impl CredentialFormatMetadata for StandardCredentialFormatMetadata {
    type Format = StandardFormat;

    type SigningAlgorithm = String;

    fn id(&self) -> StandardFormat {
        match self {
            Self::W3c(f) => StandardFormat::W3c(f.id),
            Self::MsoMdoc(_) => StandardFormat::MsoMdoc,
            Self::VcSdJwt(_) => StandardFormat::VcSdJwt,
            Self::Unknown(other) => StandardFormat::Unknown(other.id.clone()),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardCredentialAuthorizationParams {
    #[serde(flatten)]
    pub w3c_vc: Option<w3c_vc::W3cVcAuthorizationParams>,

    #[serde(flatten)]
    pub mso_mdoc: mso_mdoc::MsoMdocAuthorizationParams,

    #[serde(flatten)]
    pub vc_sd_jwt: Option<vc_sd_jwt::VcSdJwtAuthorizationParams>,
}

impl CredentialAuthorizationParams for StandardCredentialAuthorizationParams {
    type Format = StandardFormat;
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardCredentialRequestParams {
    #[serde(flatten)]
    pub w3c_vc: Option<w3c_vc::W3cVcRequestParams>,

    #[serde(flatten)]
    pub mso_mdoc: Option<mso_mdoc::MsoMdocRequestParams>,

    #[serde(flatten)]
    pub vc_sd_jwt: Option<vc_sd_jwt::VcSdJwtRequestParams>,
}

impl CredentialRequestParams for StandardCredentialRequestParams {
    type Format = StandardFormat;
}
