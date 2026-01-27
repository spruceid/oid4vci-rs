use std::fmt::Debug;

use indexmap::IndexMap;
use iref::Uri;
use oauth2::{
    http::{
        self,
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    AccessToken, AsyncHttpClient, HttpRequest, HttpResponse, SyncHttpClient,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{
    encryption::CredentialResponseEncryption,
    proof::Proofs,
    response::CredentialResponse,
    util::http::{auth_bearer, check_content_type, HttpError, MIME_TYPE_JSON},
};

/// Credential request.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(bound = "F: CredentialRequestParams")]
pub struct CredentialRequest<F: CredentialRequestParams = AnyCredentialRequestParams> {
    /// Requested credential.
    #[serde(flatten)]
    pub credential: CredentialIdentifierOrConfigurationId,

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
    pub fn new(credential: CredentialIdentifierOrConfigurationId) -> Self
    where
        F: Default,
    {
        Self::new_with(credential, F::default())
    }

    /// Creates a new Credential Request with the given format-specific
    /// parameters.
    pub fn new_with(credential: CredentialIdentifierOrConfigurationId, params: F) -> Self {
        Self {
            credential,
            proofs: None,
            credential_response_encryption: None,
            params,
        }
    }

    pub fn send<C, T>(
        self,
        http_client: &C,
        credential_endpoint: &Uri,
        access_token: &AccessToken,
    ) -> Result<CredentialResponse<T>, HttpError>
    where
        C: SyncHttpClient,
        T: DeserializeOwned,
    {
        let http_response = http_client
            .call(self.prepare_request(credential_endpoint, access_token))
            .map_err(HttpError::query(credential_endpoint))?;

        self.credential_response(credential_endpoint, http_response)
    }

    pub async fn send_async<'c, C, T>(
        self,
        http_client: &'c C,
        credential_endpoint: &Uri,
        access_token: &AccessToken,
    ) -> Result<CredentialResponse<T>, HttpError>
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
        T: DeserializeOwned,
    {
        let http_response = http_client
            .call(self.prepare_request(credential_endpoint, access_token))
            .await
            .map_err(HttpError::query(credential_endpoint))?;

        self.credential_response(credential_endpoint, http_response)
    }

    fn prepare_request(
        &self,
        credential_endpoint: &Uri,
        access_token: &AccessToken,
    ) -> HttpRequest {
        let (auth_header, auth_value) = auth_bearer(access_token);
        http::Request::builder()
            .uri(credential_endpoint.to_string())
            .method(Method::POST)
            .header(CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(auth_header, auth_value)
            .body(
                serde_json::to_vec(self)
                    // UNWRAP SAFETY: A credential request can always be serialized as JSON.
                    .unwrap(),
            )
            // UNWRAP SAFETY: Query parameters are all type safe.
            .unwrap()
    }

    fn credential_response<T>(
        self,
        uri: &Uri,
        http_response: HttpResponse,
    ) -> Result<CredentialResponse<T>, HttpError>
    where
        T: DeserializeOwned,
    {
        match http_response.status() {
            StatusCode::OK => {
                check_content_type(uri, http_response.headers(), MIME_TYPE_JSON)?;
                serde_json::from_slice(http_response.body())
                    .map(CredentialResponse::Immediate)
                    .map_err(HttpError::json(uri))
            }
            StatusCode::ACCEPTED => {
                check_content_type(uri, http_response.headers(), MIME_TYPE_JSON)?;
                serde_json::from_slice(http_response.body())
                    .map(CredentialResponse::Deferred)
                    .map_err(HttpError::json(uri))
            }
            status => Err(HttpError::ServerError(uri.to_owned(), status)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CredentialIdentifierOrConfigurationId {
    /// Identifies a Credential Dataset that is requested for issuance.
    ///
    /// To be used when the Token Response included a Credential Authorization
    /// Details Object.
    #[serde(rename = "credential_identifier")]
    Identifier(String),

    /// Identifies a Credential Configuration, defined in the
    /// Credential Issuer Metadata, that is requested for issuance.
    ///
    /// It must be a key of
    /// [`CredentialIssuerMetadata::credential_configurations_supported`].
    /// The associated [`CredentialConfiguration::scope`] value must match one
    /// of the scopes included in the Authorization Request.
    ///
    /// [`CredentialIssuerMetadata::credential_configurations_supported`]: crate::issuer::CredentialIssuerMetadata::credential_configurations_supported
    /// [`CredentialConfiguration::scope`]: crate::issuer::metadata::CredentialConfiguration::scope
    #[serde(rename = "credential_configuration_id")]
    ConfigurationId(String),
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn example_credential_request_object() {
        let _: CredentialRequest = serde_json::from_value(json!({
            "format": "jwt_vc_json",
            "credential_identifier": "UniversityDegreeCredential",
            "proofs": {
               "jwt": ["eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8
               xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR
               0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE1MzY5NTk5NTksIm5vbmNlIjoidFppZ25zbk
               ZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"]
            }
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_request_referenced() {
        let _: CredentialRequest = serde_json::from_value(json!({
            "credential_identifier": "UniversityDegreeCredential",
            "proofs": {
               "jwt": ["eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8
               xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR
               0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE1MzY5NTk5NTksIm5vbmNlIjoidFppZ25zbk
               ZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"]
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
}
