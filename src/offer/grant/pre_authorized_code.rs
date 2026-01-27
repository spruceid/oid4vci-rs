use iref::UriBuf;
use rand::{
    distr::{Alphanumeric, SampleString},
    thread_rng, CryptoRng,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,

    pub tx_code: Option<TxCodeDefinition>,

    pub interval: Option<usize>,

    pub authorization_server: Option<UriBuf>,
}

impl PreAuthorizedCodeGrant {
    pub fn new(pre_authorized_code: String) -> Self {
        Self {
            pre_authorized_code,
            tx_code: None,
            interval: None,
            authorization_server: None,
        }
    }
}

const NUMERIC: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Default)]
pub enum InputMode {
    #[serde(rename = "numeric")]
    #[default]
    Numeric,

    #[serde(rename = "text")]
    Text,
}

impl InputMode {
    pub fn generate_with(&self, rng: &mut impl CryptoRng, len: usize) -> String {
        match self {
            Self::Numeric => rand::distr::slice::Choose::new(NUMERIC)
                .unwrap()
                .sample_string(rng, len),
            Self::Text => Alphanumeric.sample_string(rng, len),
        }
    }
}

#[skip_serializing_none]
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
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

    pub fn generate(&self) -> String {
        let mut rng = thread_rng();
        let len = self.length.unwrap_or(6);
        self.input_mode
            .unwrap_or(InputMode::Text)
            .generate_with(&mut rng, len)
    }
}
