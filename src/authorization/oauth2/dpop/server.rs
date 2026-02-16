use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use ssi::jwk::Algorithm;

/// DPoP-related Authorization Server Metadata.
///
/// See: <https://www.rfc-editor.org/rfc/rfc9449#name-authorization-server-metada>
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct DpopServerParams {
    /// List of the JWS alg values supported by the authorization server for
    /// DPoP proof JWTs.
    pub dpop_signing_alg_values_supported: Vec<Algorithm>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "error", rename = "use_dpop_nonce")]
pub struct DpopErrorResponse {
    pub error_description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DpopResponse<T> {
    RequireDpop(DpopErrorResponse),
    Ok(T),
}
