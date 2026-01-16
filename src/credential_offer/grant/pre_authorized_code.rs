use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::types::{IssuerUrl, PreAuthorizedCode};

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: PreAuthorizedCode,

    pub tx_code: Option<TxCodeDefinition>,

    pub interval: Option<usize>,

    pub authorization_server: Option<IssuerUrl>,
}

impl PreAuthorizedCodeGrant {
    pub fn new(pre_authorized_code: PreAuthorizedCode) -> Self {
        Self {
            pre_authorized_code,
            tx_code: None,
            interval: None,
            authorization_server: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum InputMode {
    #[serde(rename = "numeric")]
    Numeric,
    #[serde(rename = "text")]
    Text,
}

impl Default for InputMode {
    fn default() -> Self {
        Self::Numeric
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxCodeDefinition {
    pub input_mode: Option<InputMode>,
    pub length: Option<usize>,
    pub description: Option<String>,
}

impl TxCodeDefinition {
    pub fn new(
        input_mode: Option<InputMode>,
        length: Option<usize>,
        description: Option<String>,
    ) -> Self {
        Self {
            input_mode,
            length,
            description,
        }
    }
}
