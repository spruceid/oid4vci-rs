use std::{fmt::Debug, future::Future, marker::PhantomData};

use indexmap::IndexMap;
use oauth2::{
    http::{
        self,
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    AccessToken, AsyncHttpClient, HttpRequest, HttpResponse, SyncHttpClient,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    encryption::CredentialResponseEncryption,
    profile::StandardCredentialRequestParams,
    proof_of_possession::Proof,
    response::CredentialResponse,
    types::CredentialUrl,
    util::http::{auth_bearer, content_type_has_essence, MIME_TYPE_JSON},
};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialRequestError<RE>
where
    RE: std::error::Error + 'static,
{
    #[error("Failed to parse server response")]
    Parse(#[source] serde_path_to_error::Error<serde_json::Error>),
    #[error("Request failed")]
    Request(#[source] RE),
    #[error("Server returned invalid response: {2}")]
    Response(StatusCode, Vec<u8>, String),
    #[error("Other error: {0}")]
    Other(String),
}

/// Credential request.
///
/// # Credential format or identifier.
///
/// The `F` parameter must serialize into a struct with *either* of those fields
/// - `format`: a string that determines the format of the Credential to be
///   issued.
/// - `credential_identifier`: a string that identifies a Credential that is
///   being requested to be issued.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(bound = "F: CredentialRequestParams")]
pub struct CredentialRequest<F: CredentialRequestParams = StandardCredentialRequestParams> {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,

    #[serde(flatten)]
    pub format_or_identifier: CredentialFormatOrIdentifier<F::Format>,

    #[serde(flatten)]
    pub params: F,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialFormatOrIdentifier<F> {
    #[serde(rename = "format")]
    Format(F),

    #[serde(rename = "credential_identifier")]
    Identifier(String),
}

impl<F: CredentialRequestParams> CredentialRequest<F> {
    pub(crate) fn new(
        format_or_identifier: CredentialFormatOrIdentifier<F::Format>,
        params: F,
    ) -> Self {
        Self {
            proof: None,
            credential_response_encryption: None,
            format_or_identifier,
            params,
        }
    }
}

/// Credential format request parameters.
///
/// Specifies format-specific parameters in a [`CredentialRequest`].
pub trait CredentialRequestParams: Serialize + DeserializeOwned {
    type Format: Debug + Clone + PartialEq + Eq + Serialize + DeserializeOwned;
}

pub type AnyCredentialRequestParams = IndexMap<String, serde_json::Value>;

impl CredentialRequestParams for AnyCredentialRequestParams {
    type Format = String;
}

pub struct CredentialRequestBuilder<F: CredentialRequestParams, T> {
    body: CredentialRequest<F>,
    url: CredentialUrl,
    access_token: AccessToken,
    credential_type: PhantomData<T>,
}

impl<F, T> CredentialRequestBuilder<F, T>
where
    F: CredentialRequestParams,
{
    pub(crate) fn new(
        body: CredentialRequest<F>,
        url: CredentialUrl,
        access_token: AccessToken,
    ) -> Self {
        Self {
            body,
            url,
            access_token,
            credential_type: PhantomData,
        }
    }

    pub fn format_or_identifier(&self) -> &CredentialFormatOrIdentifier<F::Format> {
        &self.body.format_or_identifier
    }

    pub fn set_format_or_identifier(
        mut self,
        format_or_identifier: CredentialFormatOrIdentifier<F::Format>,
    ) -> Self {
        self.body.format_or_identifier = format_or_identifier;
        self
    }

    pub fn proof(&self) -> &Option<Proof> {
        &self.body.proof
    }

    pub fn set_proof(mut self, proof: Option<Proof>) -> Self {
        self.body.proof = proof;
        self
    }

    pub fn credential_response_encryption(&self) -> &Option<CredentialResponseEncryption> {
        &self.body.credential_response_encryption
    }

    pub fn set_credential_response_encryption(
        mut self,
        credential_response_encryption: Option<CredentialResponseEncryption>,
    ) -> Self {
        self.body.credential_response_encryption = credential_response_encryption;
        self
    }

    pub fn request<C>(
        self,
        http_client: &C,
    ) -> Result<CredentialResponse<T>, CredentialRequestError<C::Error>>
    where
        C: SyncHttpClient,
        T: DeserializeOwned,
    {
        http_client
            .call(self.prepare_request().map_err(|err| {
                CredentialRequestError::Other(format!("failed to prepare request: {err:?}"))
            })?)
            .map_err(CredentialRequestError::Request)
            .and_then(|http_response| self.credential_response(http_response))
    }

    pub fn request_async<'c, C>(
        self,
        http_client: &'c C,
    ) -> impl Future<Output = Result<CredentialResponse<T>, CredentialRequestError<C::Error>>> + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
        T: DeserializeOwned,
    {
        Box::pin(async move {
            let http_response = http_client
                .call(self.prepare_request().map_err(|err| {
                    CredentialRequestError::Other(format!("failed to prepare request: {err:?}"))
                })?)
                .await
                .map_err(CredentialRequestError::Request)?;

            self.credential_response(http_response)
        })
    }

    fn prepare_request(&self) -> Result<HttpRequest, CredentialRequestError<http::Error>> {
        let (auth_header, auth_value) = auth_bearer(&self.access_token);
        http::Request::builder()
            .uri(self.url.to_string())
            .method(Method::POST)
            .header(CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(auth_header, auth_value)
            .body(
                serde_json::to_vec(&self.body)
                    .map_err(|e| CredentialRequestError::Other(e.to_string()))?,
            )
            .map_err(CredentialRequestError::Request)
    }

    fn credential_response<RE>(
        self,
        http_response: HttpResponse,
    ) -> Result<CredentialResponse<T>, CredentialRequestError<RE>>
    where
        T: DeserializeOwned,
        RE: std::error::Error + 'static,
    {
        // TODO status 202 if deferred
        if http_response.status() != StatusCode::OK {
            return Err(CredentialRequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                "unexpected HTTP status code".to_string(),
            ));
        }

        match http_response
            .headers()
            .get(CONTENT_TYPE)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| HeaderValue::from_static(MIME_TYPE_JSON))
        {
            ref content_type if content_type_has_essence(content_type, MIME_TYPE_JSON) => {
                serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(
                    http_response.body(),
                ))
                .map_err(CredentialRequestError::Parse)
            }
            ref content_type => Err(CredentialRequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                format!("unexpected response Content-Type: `{:?}`", content_type),
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeferredRequest {
    transaction_id: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn example_credential_request_object() {
        let _: CredentialRequest = serde_json::from_value(json!({
            "format": "jwt_vc_json",
            "credential_definition": {
             "type": [
                 "VerifiableCredential",
                 "UniversityDegreeCredential"
             ]
            },
            "proof": {
               "proof_type": "jwt",
               "jwt": "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8
               xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR
               0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE1MzY5NTk5NTksIm5vbmNlIjoidFppZ25zbk
               ZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
            }
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_request_referenced() {
        let _: CredentialRequest = serde_json::from_value(json!({
            "credential_identifier": "UniversityDegreeCredential",
            "proof": {
               "proof_type": "jwt",
               "jwt": "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8
               xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR
               0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE1MzY5NTk5NTksIm5vbmNlIjoidFppZ25zbk
               ZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
            }
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_request_deny() {
        assert!(serde_json::from_value::<CredentialRequest>(json!({
            "format": "jwt_vc_json",
            "credential_identifier": "UniversityDegreeCredential",
            "proof": {
               "proof_type": "jwt",
               "jwt": "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8
               xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR
               0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE1MzY5NTk5NTksIm5vbmNlIjoidFppZ25zbk
               ZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
            }
        }))
        .is_err());
    }

    #[test]
    fn example_deferred_request() {
        let _: DeferredRequest = serde_json::from_value(json!({
            "transaction_id":"8xLOxBtZp8"
        }))
        .unwrap();
    }
}
