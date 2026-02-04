use oauth2::{AuthorizationCode, ErrorResponseType, StandardErrorResponse};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthorizationResponse {
    pub code: AuthorizationCode,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationErrorType {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporaryUnavailable,
}

impl AuthorizationErrorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthorizationErrorType::InvalidRequest => "invalid_request",
            AuthorizationErrorType::UnauthorizedClient => "unauthorized_client",
            AuthorizationErrorType::AccessDenied => "access_denied",
            AuthorizationErrorType::UnsupportedResponseType => "unsupported_response_type",
            AuthorizationErrorType::InvalidScope => "invalid_scope",
            AuthorizationErrorType::ServerError => "server_error",
            AuthorizationErrorType::TemporaryUnavailable => "temporarily_unavailable",
        }
    }
}

impl ErrorResponseType for AuthorizationErrorType {}

pub type AuthorizationErrorResponse = StandardErrorResponse<AuthorizationErrorType>;

#[derive(Deserialize)]
#[serde(untagged)]
pub enum AuthorizationResponseResult {
    Ok(AuthorizationResponse),
    Err(AuthorizationErrorResponse),
}
