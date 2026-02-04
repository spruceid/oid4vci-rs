use serde::{Deserialize, Serialize};

/// Nonce Response.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-response>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    pub c_nonce: String,
}

/// Axum support.
#[cfg(feature = "axum")]
mod axum {
    use ::axum::{
        body::Body,
        http::{
            header::{CACHE_CONTROL, CONTENT_TYPE},
            StatusCode,
        },
        response::{IntoResponse, Response},
    };

    use crate::util::http::MIME_TYPE_JSON;

    use super::*;

    impl IntoResponse for NonceResponse {
        fn into_response(self) -> Response {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, MIME_TYPE_JSON)
                .header(CACHE_CONTROL, "no-store")
                .body(Body::from(
                    serde_json::to_vec(&self)
                        // UNWRAP SAFETY: Nonce Response is always serializable as JSON.
                        .unwrap(),
                ))
                .unwrap()
        }
    }
}
