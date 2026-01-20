use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{authorization::CredentialAuthorizationParams, profile::vc_sd_jwt::VcSdJwtFormat};

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcSdJwtAuthorizationParams {
    pub vct: Option<String>,

    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub claims: IndexMap<String, VcSdJwtClaimAuthorization>,
}

impl CredentialAuthorizationParams for VcSdJwtAuthorizationParams {
    type Format = VcSdJwtFormat;
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcSdJwtClaimAuthorization {
    #[serde(default, skip_serializing_if = "crate::util::is_false")]
    pub mandatory: bool,
}
