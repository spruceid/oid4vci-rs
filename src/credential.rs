use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct Oid4vciCredential<T = serde_json::Value> {
    #[serde(rename = "credential")]
    pub value: T,
}

impl<T> Oid4vciCredential<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }
}
