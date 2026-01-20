use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::types::LanguageTag;

use super::VcSdJwtFormat;

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcSdJwtFormatMetadata {
    #[serde(rename = "format")]
    pub id: VcSdJwtFormat,

    pub vct: String,

    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub claims: IndexMap<String, VcSdJwtClaimMetadata>,

    pub order: Option<Vec<String>>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcSdJwtClaimMetadata {
    #[serde(default, skip_serializing_if = "is_false")]
    pub mandatory: bool,

    pub value_type: Option<String>,

    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub display: Vec<VcSdJwtClaimDisplay>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcSdJwtClaimDisplay {
    pub name: Option<String>,

    pub locale: Option<LanguageTag>,
}
