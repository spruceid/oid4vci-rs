use iref::Uri;
use open_auth2::{
    client::{OAuth2Client, OAuth2ClientError},
    endpoints::{Endpoint, HttpRequest, RequestBuilder},
    http,
    server::ErrorResponse,
    transport::{HttpClient, Json},
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

pub struct NotificationEndpoint<'a, C> {
    pub client: &'a C,
    pub uri: &'a Uri,
}

impl<'a, C> NotificationEndpoint<'a, C> {
    pub fn new(client: &'a C, uri: &'a Uri) -> Self {
        Self { client, uri }
    }

    pub fn notify(
        self,
        notification_id: String,
        event: NotificationEventType,
        event_description: Option<String>,
    ) -> RequestBuilder<Self, NotificationRequest> {
        RequestBuilder::new(
            self,
            NotificationRequest::new(notification_id, event, event_description),
        )
    }
}

impl<'a, C> Endpoint for NotificationEndpoint<'a, C>
where
    C: OAuth2Client,
{
    type Client = C;

    fn client(&self) -> &Self::Client {
        self.client
    }

    fn uri(&self) -> &Uri {
        self.uri
    }
}

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
    pub notification_id: String,

    /// Notification event type.
    pub event: NotificationEventType,

    /// Human-readable description.
    ///
    /// Used to assist the Credential Issuer developer in understanding the
    /// event that occurred.
    pub event_description: Option<String>,
}

impl NotificationRequest {
    pub fn new(
        notification_id: String,
        event: NotificationEventType,
        event_description: Option<String>,
    ) -> Self {
        Self {
            notification_id,
            event,
            event_description,
        }
    }
}

impl<'a, C> HttpRequest<NotificationEndpoint<'a, C>> for NotificationRequest {
    type ContentType = Json;
    type RequestBody<'b>
        = &'b Self
    where
        Self: 'b;

    type Response = ();
    type ResponsePayload = ();

    async fn build_request(
        &self,
        endpoint: &NotificationEndpoint<'a, C>,
        _http_client: &impl HttpClient,
    ) -> Result<http::Request<Self::RequestBody<'_>>, OAuth2ClientError> {
        Ok(http::Request::builder()
            .method(http::Method::POST)
            .uri(endpoint.uri.as_str())
            .body(self)
            .unwrap())
    }

    fn decode_response(
        &self,
        _endpoint: &NotificationEndpoint<'a, C>,
        response: http::Response<Vec<u8>>,
    ) -> Result<http::Response<Self::ResponsePayload>, OAuth2ClientError> {
        // TODO error handling.
        Ok(response.map(|_| ()))
    }

    async fn process_response(
        &self,
        _endpoint: &NotificationEndpoint<'a, C>,
        _http_client: &impl HttpClient,
        response: http::Response<Self::ResponsePayload>,
    ) -> Result<Self::Response, OAuth2ClientError> {
        response.into_body();
        Ok(())
    }
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

// /// Notification Error Response.
// ///
// /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-error-response>
// pub type NotificationErrorResponse = StandardErrorResponse<NotificationErrorType>;

/// Notification Error Type.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-error-response>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum NotificationError {
    #[serde(rename = "invalid_notification_id")]
    InvalidNotificationId,

    #[serde(rename = "invalid_notification_request")]
    InvalidNotificationRequest,
}

// impl ErrorResponseType for NotificationErrorType {}

pub type NotificationErrorResponse = ErrorResponse<NotificationError>;

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
