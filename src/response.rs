use oauth2::{ErrorResponseType, StandardErrorResponse};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::Oid4vciCredential;

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CredentialResponse<T = serde_json::Value> {
    Immediate(ImmediateCredentialResponse<T>),
    Deferred(DeferredCredentialResponse),
}

#[skip_serializing_none]
#[derive(Debug, Deserialize, Serialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct ImmediateCredentialResponse<T = serde_json::Value> {
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub credentials: Vec<Oid4vciCredential<T>>,

    /// Identifies one or more Credentials issued in one Credential Response.
    ///
    /// It *must* be included in the Notification Request.
    pub notification_id: Option<String>,
}

impl<T> ImmediateCredentialResponse<T> {
    pub fn new(credentials: Vec<Oid4vciCredential<T>>) -> Self {
        Self {
            credentials,
            notification_id: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeferredCredentialResponse {
    pub transaction_id: String,

    pub interval: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ResponseKind<T> {
    #[serde(rename = "credentials")]
    Immediate { credentials: Vec<T> },

    #[serde(rename = "transaction_id")]
    Deferred { transaction_id: Option<String> },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    InvalidToken,
    InvalidCredentialRequest,
    UnsupportedCredentialType,
    UnsupportedCredentialFormat,
    InvalidProof,
    InvalidEncryptionParameters,
}
impl ErrorResponseType for ErrorType {}

pub type ErrorResponse = StandardErrorResponse<ErrorType>;

#[cfg(feature = "axum")]
mod axum {
    use ::axum::{
        body::Body,
        http::{header::CONTENT_TYPE, StatusCode},
        response::{IntoResponse, Response},
    };

    use crate::util::http::MIME_TYPE_JSON;

    use super::*;

    impl<T: Serialize> IntoResponse for ImmediateCredentialResponse<T> {
        fn into_response(self) -> Response {
            // This library doesn't enforce through the type system that the
            // credential payload *must* be serializable as JSON, so the
            // serialization may fail here.
            match serde_json::to_vec(&self) {
                Ok(json) => {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, MIME_TYPE_JSON)
                        .body(Body::from(json))
                        // UNWRAP SAFETY: A Credential Response is always a valid HTTP
                        //                response.
                        .unwrap()
                }
                Err(_) => {
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::default())
                        // UNWRAP SAFETY: Such error response is always a valid
                        //                HTTP response.
                        .unwrap()
                }
            }
        }
    }

    impl IntoResponse for DeferredCredentialResponse {
        fn into_response(self) -> Response {
            Response::builder()
                .status(StatusCode::ACCEPTED)
                .header(CONTENT_TYPE, MIME_TYPE_JSON)
                .body(Body::from(
                    serde_json::to_vec(&self)
                        // UNWRAP SAFETY: A Deferred Credential Response is
                        //                always serializable as JSON.
                        .unwrap(),
                ))
                // UNWRAP SAFETY: A Credential Response is always a valid HTTP
                //                response.
                .unwrap()
        }
    }

    impl<T: Serialize> IntoResponse for CredentialResponse<T> {
        fn into_response(self) -> Response {
            match self {
                Self::Immediate(i) => i.into_response(),
                Self::Deferred(d) => d.into_response(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn example_credential_response_object() {
        let _: ImmediateCredentialResponse = serde_json::from_value(json!({
            "format": "jwt_vc_json",
            "credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L",
            "c_nonce": "fGFF7UkhLa",
            "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_deferred_response_object() {
        let _: ImmediateCredentialResponse = serde_json::from_value(json!({
            "transaction_id": "8xLOxBtZp8",
            "c_nonce": "wlbQc6pCJp",
            "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }

    #[test]
    fn example_error() {
        let _: ErrorResponse = serde_json::from_value(json!({
            "error": "invalid_proof",
            "error_description": "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.",
            "c_nonce": "8YE9hCnyV2",
            "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }
}
