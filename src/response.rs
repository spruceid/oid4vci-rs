use oauth2::{ErrorResponseType, StandardErrorResponse};
use serde::{Deserialize, Serialize};

use crate::{profiles::CredentialResponseProfile, types::Nonce};

#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialResponse<CR>
where
    CR: CredentialResponseProfile,
{
    #[serde(flatten, bound = "CR: CredentialResponseProfile")]
    pub response_kind: ResponseKind<CR>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<Nonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<i64>,
}

impl<CR> CredentialResponse<CR>
where
    CR: CredentialResponseProfile,
{
    pub fn new(response_kind: ResponseKind<CR>) -> Self {
        Self {
            response_kind,
            c_nonce: None,
            c_nonce_expires_in: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ResponseKind<CR>
where
    CR: CredentialResponseProfile,
{
    #[serde(bound = "CR: CredentialResponseProfile")]
    Immediate {
        credential: CR::Type,
    },
    /// Support for multiple credentials of a specific type from the latest working draft versions.
    #[serde(bound = "CR: CredentialResponseProfile")]
    ImmediateMany {
        credentials: Vec<CR::Type>,
    },
    Deferred {
        transaction_id: Option<String>,
    },
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::profiles::core::profiles::CoreProfilesCredentialResponse;

    use super::*;

    #[test]
    fn example_credential_response_object() {
        let _: CredentialResponse<CoreProfilesCredentialResponse> = serde_json::from_value(json!({
            "format": "jwt_vc_json",
            "credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L",
            "c_nonce": "fGFF7UkhLa",
            "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_deferred_response_object() {
        let _: CredentialResponse<CoreProfilesCredentialResponse> = serde_json::from_value(json!({
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
