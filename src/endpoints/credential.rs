use indexmap::IndexMap;
use iref::Uri;
use open_auth2::{
    client::{OAuth2Client, OAuth2ClientError},
    endpoints::{Endpoint, HttpRequest, RequestBuilder},
    http,
    transport::{expect_content_type, HttpClient, Json, APPLICATION_JSON},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{
    client::Oid4vciClient, credential::CredentialOrConfigurationId,
    encryption::CredentialResponseEncryption, proof::Proofs, Oid4vciCredential, Profile,
};

pub struct CredentialEndpoint<'a, C> {
    pub client: &'a C,
    pub uri: &'a Uri,
}

impl<'a, C> CredentialEndpoint<'a, C> {
    pub fn new(client: &'a C, uri: &'a Uri) -> Self {
        Self { client, uri }
    }

    pub fn exchange_credential<F: CredentialRequestParams>(
        self,
        credential: CredentialOrConfigurationId,
        proofs: Option<Proofs>,
        credential_response_encryption: Option<CredentialResponseEncryption>,
        params: F,
    ) -> RequestBuilder<Self, CredentialRequest<F>> {
        RequestBuilder::new(
            self,
            CredentialRequest {
                credential,
                proofs,
                credential_response_encryption,
                params,
            },
        )
    }
}

impl<'a, C> Endpoint for CredentialEndpoint<'a, C>
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

impl<'a, C> Clone for CredentialEndpoint<'a, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, C> Copy for CredentialEndpoint<'a, C> {}

/// Credential request.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(bound = "F: CredentialRequestParams")]
pub struct CredentialRequest<F: CredentialRequestParams = AnyCredentialRequestParams> {
    /// Requested credential.
    #[serde(flatten)]
    pub credential: CredentialOrConfigurationId,

    /// Proofs of possession.
    pub proofs: Option<Proofs>,

    pub credential_response_encryption: Option<CredentialResponseEncryption>,

    /// Additional format-specific parameters.
    #[serde(flatten)]
    pub params: F,
}

impl<F: CredentialRequestParams> CredentialRequest<F> {
    /// Creates a new Credential Request.
    ///
    /// This will use the default format-specific parameters.
    pub fn new(credential: CredentialOrConfigurationId) -> Self
    where
        F: Default,
    {
        Self::new_with(credential, F::default())
    }

    /// Creates a new Credential Request with the given format-specific
    /// parameters.
    pub fn new_with(credential: CredentialOrConfigurationId, params: F) -> Self {
        Self {
            credential,
            proofs: None,
            credential_response_encryption: None,
            params,
        }
    }
}

impl<'a, C, F> HttpRequest<CredentialEndpoint<'a, C>> for CredentialRequest<F>
where
    F: CredentialRequestParams,
    C: Oid4vciClient,
{
    type ContentType = Json;
    type RequestBody<'b>
        = &'b Self
    where
        Self: 'b;
    type Response = CredentialResponse<<C::Profile as Profile>::Credential>;
    type ResponsePayload = CredentialResponse<<C::Profile as Profile>::Credential>;

    async fn build_request(
        &self,
        endpoint: &CredentialEndpoint<'a, C>,
        _http_client: &impl HttpClient,
    ) -> Result<http::Request<Self::RequestBody<'_>>, open_auth2::client::OAuth2ClientError> {
        Ok(http::Request::builder()
            .method(http::Method::POST)
            .uri(endpoint.uri.as_str())
            .header(http::header::ACCEPT, &APPLICATION_JSON)
            .body(self)
            .unwrap())
    }

    fn decode_response(
        &self,
        _endpoint: &CredentialEndpoint<'a, C>,
        response: http::Response<Vec<u8>>,
    ) -> Result<http::Response<Self::ResponsePayload>, OAuth2ClientError> {
        match response.status() {
            http::StatusCode::OK => {
                expect_content_type(response.headers(), &APPLICATION_JSON)?;
                let body =
                    serde_json::from_slice(response.body()).map_err(OAuth2ClientError::response)?;
                Ok(response.map(|_| CredentialResponse::Immediate(body)))
            }
            http::StatusCode::ACCEPTED => {
                expect_content_type(response.headers(), &APPLICATION_JSON)?;
                let body =
                    serde_json::from_slice(response.body()).map_err(OAuth2ClientError::response)?;
                Ok(response.map(|_| CredentialResponse::Deferred(body)))
            }
            status => Err(OAuth2ClientError::ServerError(status)),
        }
    }

    async fn process_response(
        &self,
        _endpoint: &CredentialEndpoint<'a, C>,
        _http_client: &impl HttpClient,
        response: http::Response<Self::ResponsePayload>,
    ) -> Result<Self::Response, open_auth2::client::OAuth2ClientError> {
        Ok(response.into_body())
    }
}

/// Credential format request parameters.
///
/// Specifies format-specific parameters in a [`CredentialRequest`].
pub trait CredentialRequestParams: Send + Sync + Serialize + DeserializeOwned + 'static {}

pub type AnyCredentialRequestParams = IndexMap<String, serde_json::Value>;

impl CredentialRequestParams for AnyCredentialRequestParams {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeferredCredentialRequest {
    pub transaction_id: String,
}

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

#[cfg(feature = "axum")]
mod axum {
    use ::axum::{
        body::Body,
        http::{header::CONTENT_TYPE, StatusCode},
        response::{IntoResponse, Response},
    };
    use open_auth2::transport::APPLICATION_JSON;

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
                        .header(CONTENT_TYPE, &APPLICATION_JSON)
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
                .header(CONTENT_TYPE, &APPLICATION_JSON)
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
    use open_auth2::server::ErrorResponse;
    use serde_json::json;

    use super::*;

    #[test]
    fn example_credential_request_object() {
        let _: CredentialRequest = serde_json::from_value(json!({
            "format": "jwt_vc_json",
            "credential_identifier": "UniversityDegreeCredential",
            "proofs": {
               "jwt": ["eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE1MzY5NTk5NTksIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"]
            }
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_request_referenced() {
        let _: CredentialRequest = serde_json::from_value(json!({
            "credential_identifier": "UniversityDegreeCredential",
            "proofs": {
               "jwt": ["eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE1MzY5NTk5NTksIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"]
            }
        }))
        .unwrap();
    }

    #[test]
    fn example_deferred_request() {
        let _: DeferredCredentialRequest = serde_json::from_value(json!({
            "transaction_id":"8xLOxBtZp8"
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_response_object() {
        let _: ImmediateCredentialResponse = serde_json::from_value(json!({
            "credentials": [{"credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L"}]
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_deferred_response_object() {
        let _: DeferredCredentialResponse = serde_json::from_value(json!({
            "transaction_id": "8xLOxBtZp8",
            "interval": 12
        }))
        .unwrap();
    }

    #[test]
    fn example_error() {
        let _: ErrorResponse = serde_json::from_value(json!({
            "error": "invalid_proof",
            "error_description": "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.",
        }))
        .unwrap();
    }
}
