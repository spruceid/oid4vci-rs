use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::request::CredentialRequestParams;

use super::{DcSdJwtClaimMetadata, DcSdJwtFormat};

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcSdJwtRequestParams {
    pub vct: Option<String>,

    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub claims: IndexMap<String, DcSdJwtClaimMetadata>,
}

impl CredentialRequestParams for DcSdJwtRequestParams {
    type Format = DcSdJwtFormat;
}
