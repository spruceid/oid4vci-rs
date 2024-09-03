use std::future::Future;

use oauth2::{
    http::{
        self,
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    AccessToken, AsyncHttpClient, ErrorResponseType, HttpRequest, HttpResponse,
    StandardErrorResponse, SyncHttpClient,
};
use serde::{Deserialize, Serialize};

use crate::{
    credential_response_encryption::CredentialResponseEncryption,
    http_utils::{auth_bearer, content_type_has_essence, MIME_TYPE_JSON},
    profiles::{CredentialRequestProfile, CredentialResponseProfile},
    proof_of_possession::Proof,
    types::{BatchCredentialUrl, CredentialUrl, Nonce},
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request<CR>
where
    CR: CredentialRequestProfile,
{
    #[serde(flatten, bound = "CR: CredentialRequestProfile")]
    additional_profile_fields: CR,
    proof: Option<Proof>,
    credential_response_encryption: Option<CredentialResponseEncryption>,
}

impl<CR> Request<CR>
where
    CR: CredentialRequestProfile,
{
    pub(crate) fn new(additional_profile_fields: CR) -> Self {
        Self {
            additional_profile_fields,
            proof: None,
            credential_response_encryption: None,
        }
    }

    field_getters_setters![
        pub self [self] ["credential request value"] {
            set_additional_profile_fields -> additional_profile_fields[CR],
            set_proof -> proof[Option<Proof>],
            set_credential_response_encryption -> credential_response_encryption[Option<CredentialResponseEncryption>],
        }
    ];
}

pub struct RequestBuilder<CR>
where
    CR: CredentialRequestProfile,
{
    body: Request<CR>,
    url: CredentialUrl,
    access_token: AccessToken,
}

impl<CR> RequestBuilder<CR>
where
    CR: CredentialRequestProfile,
{
    pub(crate) fn new(body: Request<CR>, url: CredentialUrl, access_token: AccessToken) -> Self {
        Self {
            body,
            url,
            access_token,
        }
    }

    field_getters_setters![
        pub self [self.body] ["credential request value"] {
            set_additional_profile_fields -> additional_profile_fields[CR],
            set_proof -> proof[Option<Proof>],
            set_credential_response_encryption -> credential_response_encryption[Option<CredentialResponseEncryption>],
        }
    ];

    pub fn request<C>(
        self,
        http_client: &C,
    ) -> Result<Response<CR::Response>, RequestError<<C as SyncHttpClient>::Error>>
    where
        C: SyncHttpClient,
    {
        http_client
            .call(self.prepare_request().map_err(|err| {
                RequestError::Other(format!("failed to prepare request: {err:?}"))
            })?)
            .map_err(RequestError::Request)
            .and_then(|http_response| self.credential_response(http_response))
    }

    pub fn request_async<'c, C>(
        self,
        http_client: &'c C,
    ) -> impl Future<
        Output = Result<Response<CR::Response>, RequestError<<C as AsyncHttpClient<'c>>::Error>>,
    > + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
    {
        Box::pin(async move {
            let http_response = http_client
                .call(self.prepare_request().map_err(|err| {
                    RequestError::Other(format!("failed to prepare request: {err:?}"))
                })?)
                .await
                .map_err(RequestError::Request)?;

            self.credential_response(http_response)
        })
    }

    fn prepare_request(&self) -> Result<HttpRequest, RequestError<http::Error>> {
        let (auth_header, auth_value) = auth_bearer(&self.access_token);
        http::Request::builder()
            .uri(self.url.to_string())
            .method(Method::POST)
            .header(CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(auth_header, auth_value)
            .body(serde_json::to_vec(&self.body).map_err(|e| RequestError::Other(e.to_string()))?)
            .map_err(RequestError::Request)
    }

    fn credential_response<RE>(
        self,
        http_response: HttpResponse,
    ) -> Result<Response<CR::Response>, RequestError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        // TODO status 202 if deferred
        if http_response.status() != StatusCode::OK {
            return Err(RequestError::Response(
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
                .map_err(RequestError::Parse)
            }
            ref content_type => Err(RequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                format!("unexpected response Content-Type: `{:?}`", content_type),
            )),
        }
    }
}

pub struct BatchRequestBuilder<CR>
where
    CR: CredentialRequestProfile,
{
    body: BatchRequest<CR>,
    url: BatchCredentialUrl,
    access_token: AccessToken,
}

impl<CR> BatchRequestBuilder<CR>
where
    CR: CredentialRequestProfile,
{
    pub(crate) fn new(
        body: BatchRequest<CR>,
        url: BatchCredentialUrl,
        access_token: AccessToken,
    ) -> Self {
        Self {
            body,
            url,
            access_token,
        }
    }

    pub fn set_proofs<RE>(
        mut self,
        proofs_of_possession: Vec<Proof>,
    ) -> Result<Self, RequestError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        let req_count = self.body.credential_requests.len();
        let pop_count = proofs_of_possession.len();
        if req_count != pop_count {
            return Err(RequestError::Other(format!(
                "invalid proof count: expected {req_count}; found {pop_count}"
            )));
        }

        self.body.credential_requests = self
            .body
            .credential_requests
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, req)| req.set_proof(Some(proofs_of_possession.get(i).unwrap().to_owned())))
            .collect();

        Ok(self)
    }

    pub fn request<C>(
        self,
        http_client: &C,
    ) -> Result<BatchResponse<CR::Response>, RequestError<<C as SyncHttpClient>::Error>>
    where
        C: SyncHttpClient,
    {
        http_client
            .call(self.prepare_request().map_err(|err| {
                RequestError::Other(format!("failed to prepare request: {err:?}"))
            })?)
            .map_err(RequestError::Request)
            .and_then(|http_response| self.credential_response(http_response))
    }

    pub fn request_async<'c, C>(
        self,
        http_client: &'c C,
    ) -> impl Future<
        Output = Result<
            BatchResponse<CR::Response>,
            RequestError<<C as AsyncHttpClient<'c>>::Error>,
        >,
    > + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
    {
        Box::pin(async move {
            let http_response = http_client
                .call(self.prepare_request().map_err(|err| {
                    RequestError::Other(format!("failed to prepare request: {err:?}"))
                })?)
                .await
                .map_err(RequestError::Request)?;

            self.credential_response(http_response)
        })
    }

    fn prepare_request(&self) -> Result<HttpRequest, RequestError<http::Error>> {
        let (auth_header, auth_value) = auth_bearer(&self.access_token);
        http::Request::builder()
            .uri(self.url.to_string())
            .method(Method::POST)
            .header(CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .header(auth_header, auth_value)
            .body(serde_json::to_vec(&self.body).map_err(|e| RequestError::Other(e.to_string()))?)
            .map_err(RequestError::Request)
    }

    fn credential_response<RE>(
        self,
        http_response: HttpResponse,
    ) -> Result<BatchResponse<CR::Response>, RequestError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        // TODO status 202 if deferred
        if http_response.status() != StatusCode::OK {
            return Err(RequestError::Response(
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
                .map_err(RequestError::Parse)
            }
            ref content_type => Err(RequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                format!("unexpected response Content-Type: `{:?}`", content_type),
            )),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RequestError<RE>
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

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Response<CR>
where
    CR: CredentialResponseProfile,
{
    #[serde(flatten, bound = "CR: CredentialResponseProfile")]
    additional_profile_fields: ResponseEnum<CR>,
    c_nonce: Option<Nonce>,
    c_nonce_expires_in: Option<i64>,
}

impl<CR> Response<CR>
where
    CR: CredentialResponseProfile,
{
    pub fn new(additional_profile_fields: ResponseEnum<CR>) -> Self {
        Self {
            additional_profile_fields,
            c_nonce: None,
            c_nonce_expires_in: None,
        }
    }
    field_getters_setters![
        pub self [self] ["credential response value"] {
            set_additional_profile_fields -> additional_profile_fields[ResponseEnum<CR>],
            set_nonce -> c_nonce[Option<Nonce>],
            set_nonce_expiration -> c_nonce_expires_in[Option<i64>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ResponseEnum<CR>
where
    CR: CredentialResponseProfile,
{
    #[serde(bound = "CR: CredentialResponseProfile")]
    Immediate(CR),
    Deferred {
        transaction_id: Option<String>, // must be present if credential is None (is the profile)
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
pub type Error = StandardErrorResponse<ErrorType>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BatchRequest<CR>
where
    CR: CredentialRequestProfile,
{
    #[serde(bound = "CR: CredentialRequestProfile")]
    credential_requests: Vec<Request<CR>>,
}

impl<CR> BatchRequest<CR>
where
    CR: CredentialRequestProfile,
{
    pub fn new(credential_requests: Vec<Request<CR>>) -> Self {
        Self {
            credential_requests,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BatchResponse<CR>
where
    CR: CredentialResponseProfile,
{
    #[serde(bound = "CR: CredentialResponseProfile")]
    credential_responses: Vec<ResponseEnum<CR>>,
    c_nonce: Option<Nonce>,
    c_nonce_expires_in: Option<i64>,
}

impl<CR> BatchResponse<CR>
where
    CR: CredentialResponseProfile,
{
    pub fn new(credential_responses: Vec<ResponseEnum<CR>>) -> Self {
        Self {
            credential_responses,
            c_nonce: None,
            c_nonce_expires_in: None,
        }
    }
    field_getters_setters![
        pub self [self] ["batch credential response value"] {
            set_credential_responses -> credential_responses[Vec<ResponseEnum<CR>>],
            set_nonce -> c_nonce[Option<Nonce>],
            set_nonce_expiration -> c_nonce_expires_in[Option<i64>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeferredRequest {
    transaction_id: String,
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::core::profiles::CoreProfilesResponse;

    use super::*;

    #[test]
    fn example_credential_request_object() {
        let _: crate::core::credential::Request = serde_json::from_value(json!({
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
        let _: crate::core::credential::Request = serde_json::from_value(json!({
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
        assert!(
            serde_json::from_value::<crate::core::credential::Request>(json!({
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
            .is_err()
        );
    }

    #[test]
    fn example_credential_response_object() {
        let _: Response<CoreProfilesResponse> = serde_json::from_value(json!({
            "format": "jwt_vc_json",
            "credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L",
            "c_nonce": "fGFF7UkhLa",
            "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_deferred_response_object() {
        let _: Response<CoreProfilesResponse> = serde_json::from_value(json!({
            "transaction_id": "8xLOxBtZp8",
            "c_nonce": "wlbQc6pCJp",
            "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }

    #[test]
    fn example_error() {
        let _: Error = serde_json::from_value(json!({
            "error": "invalid_proof",
            "error_description": "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.",
            "c_nonce": "8YE9hCnyV2",
            "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }

    #[test]
    fn example_batch_request() {
        let _: crate::core::credential::BatchRequest = serde_json::from_value(json!({
            "credential_requests":[
              {
                 "format":"jwt_vc_json",
                 "credential_definition": {
                   "type":[
                     "VerifiableCredential",
                     "UniversityDegreeCredential"
                   ]
                 },
                 "proof":{
                    "proof_type":"jwt",
                    "jwt":"eyJraWQiOiJkaWQ6ZXhhbXBsZTpl...C_aZKPxgihac0aW9EkL1nOzM"
                 }
              },
              {
                 "format":"mso_mdoc",
                 "doctype":"org.iso.18013.5.1.mDL",
                 "proof":{
                    "proof_type":"jwt",
                    "jwt":"eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM"
                 }
              }
           ]
        }))
        .unwrap();
    }

    #[test]
    fn example_batch_response() {
        let _: BatchResponse<CoreProfilesResponse> = serde_json::from_value(json!({
            "credential_responses": [{
                "format": "jwt_vc_json",
                "credential": "eyJraWQiOiJkaWQ6ZXhhbXBsZTpl...C_aZKPxgihac0aW9EkL1nOzM"
              },
              {
                "format": "mso_mdoc",
                "credential": "YXNkZnNhZGZkamZqZGFza23....29tZTIzMjMyMzIzMjMy"
              }],
              "c_nonce": "fGFF7UkhLa",
              "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }

    #[test]
    fn example_batch_response_with_deferred() {
        let _: BatchResponse<CoreProfilesResponse> = serde_json::from_value(json!({
            "credential_responses":[
              {
                 "transaction_id":"8xLOxBtZp8"
              },
              {
                 "format":"jwt_vc_json",
                 "credential":"YXNkZnNhZGZkamZqZGFza23....29tZTIzMjMyMzIzMjMy"
              }
           ],
           "c_nonce":"fGFF7UkhLa",
           "c_nonce_expires_in":86400
        }))
        .unwrap();
    }

    #[test]
    fn example_deferred_request() {
        let _: DeferredRequest = serde_json::from_value(json!({
            "transaction_id":"8xLOxBtZp8"
        }))
        .unwrap();
    }
}
