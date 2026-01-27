use oauth2::{ErrorResponseType, StandardErrorResponse};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Notification Request.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-request>
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NotificationRequest {
    /// Notification identifier.
    ///
    /// String received in the Credential Response or Deferred Credential
    /// Response identifying an issuance flow that contained one or more
    /// Credentials with the same Credential Configuration and Credential
    /// Dataset.
    notification_id: String,

    /// Notification event type.
    event: NotificationEventType,

    /// Human-readable description.
    ///
    /// Used to assist the Credential Issuer developer in understanding the
    /// event that occurred.
    event_description: Option<String>,
}

/// Notification event type.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-request>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum NotificationEventType {
    /// Credential was successfully stored in the Wallet.
    #[serde(rename = "credential_accepted")]
    CredentialAccepted,

    /// Credential issuance was unsuccessful because of a user action.
    #[serde(rename = "credential_failure")]
    CredentialFailure,

    /// Credential issuance was unsuccessful for any reason other than a user
    /// action.
    #[serde(rename = "credential_deleted")]
    CredentialDeleted,
}

/// Notification Error Response.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-error-response>
pub type NotificationErrorResponse = StandardErrorResponse<NotificationErrorType>;

/// Notification Error Type.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-error-response>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum NotificationErrorType {
    #[serde(rename = "invalid_notification_id")]
    InvalidNotificationId,

    #[serde(rename = "invalid_notification_request")]
    InvalidNotificationRequest,
}

impl ErrorResponseType for NotificationErrorType {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn example_notification_request() {
        let _: NotificationRequest = serde_json::from_value(json!({
            "notification_id": "3fwe98js",
            "event": "credential_accepted"
        }))
        .unwrap();
    }

    #[test]
    fn example_notification_request_with_description() {
        let _: NotificationRequest = serde_json::from_value(json!({
            "notification_id": "3fwe98js",
            "event": "credential_failure",
            "event_description": "Could not store the Credential. Out of storage."
        }))
        .unwrap();
    }

    #[test]
    fn example_notification_error_response() {
        let _: NotificationErrorResponse = serde_json::from_value(json!({
            "error": "invalid_notification_id"
        }))
        .unwrap();
    }
}
