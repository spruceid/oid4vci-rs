#![allow(clippy::type_complexity)]

use oauth2::{ErrorResponseType, StandardErrorResponse};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum NotificationRequestEvent {
    #[serde(rename = "credential_accepted")]
    CredentialAccepted,
    #[serde(rename = "credential_failure")]
    CredentialFailure,
    #[serde(rename = "credential_deleted")]
    CredentialDeleted,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NotificationRequest {
    notification_id: String,
    event: NotificationRequestEvent,
    event_description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum NotificationErrorCode {
    #[serde(rename = "invalid_notification_id")]
    InvalidNotificationId,
    #[serde(rename = "invalid_notification_request")]
    InvalidNotificationRequest,
}
impl ErrorResponseType for NotificationErrorCode {}
pub type NotificationErrorResponse = StandardErrorResponse<NotificationErrorCode>;

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
