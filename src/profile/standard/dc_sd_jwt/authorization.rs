use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{authorization::CredentialAuthorizationParams, profile::dc_sd_jwt::DcSdJwtFormat};

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcSdJwtAuthorizationParams {
    pub vct: Option<String>,

    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub claims: IndexMap<String, DcSdJwtClaimAuthorization>,
}

impl CredentialAuthorizationParams for DcSdJwtAuthorizationParams {
    type Format = DcSdJwtFormat;
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcSdJwtClaimAuthorization {
    #[serde(default, skip_serializing_if = "crate::util::is_false")]
    pub mandatory: bool,
}
