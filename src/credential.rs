use std::{future::Future, marker::PhantomData};

use oauth2::{
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    AccessToken, HttpRequest, HttpResponse, StandardErrorResponse,
};
use openidconnect::{
    ClaimsVerificationError, ErrorResponseType, JsonWebKeyType, JweContentEncryptionAlgorithm,
    JweKeyManagementAlgorithm, Nonce,
};
use serde::{Deserialize, Serialize};
use ssi_jwk::JWK;

use crate::{
    http_utils::{auth_bearer, content_type_has_essence, MIME_TYPE_JSON},
    metadata::CredentialUrl,
    profiles::{CredentialRequestProfile, CredentialResponseProfile},
    proof_of_possession::Proof,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request<CR, JT, JE, JA>
where
    CR: CredentialRequestProfile,
    JT: JsonWebKeyType,
    JE: JweContentEncryptionAlgorithm<JT>,
    JA: JweKeyManagementAlgorithm,
{
    #[serde(flatten, bound = "CR: CredentialRequestProfile")]
    additional_profile_fields: CR,
    proof: Option<Proof>,
    credential_encryption_jwk: Option<JWK>,
    #[serde(bound = "JA: JweKeyManagementAlgorithm")]
    credential_response_encryption_alg: Option<JA>,
    #[serde(bound = "JE: JweContentEncryptionAlgorithm<JT>")]
    credential_response_encryption_enc: Option<JE>,
    #[serde(skip)]
    _phantom_jt: PhantomData<JT>,
}

impl<CR, JT, JE, JA> Request<CR, JT, JE, JA>
where
    CR: CredentialRequestProfile,
    JT: JsonWebKeyType,
    JE: JweContentEncryptionAlgorithm<JT>,
    JA: JweKeyManagementAlgorithm,
{
    pub(crate) fn new(additional_profile_fields: CR) -> Self {
        Self {
            additional_profile_fields,
            proof: None,
            credential_encryption_jwk: None,
            credential_response_encryption_alg: None,
            credential_response_encryption_enc: None,
            _phantom_jt: PhantomData,
        }
    }

    field_getters_setters![
        pub self [self] ["credential request value"] {
            set_additional_profile_fields -> additional_profile_fields[CR],
            set_proof -> proof[Option<Proof>],
            set_credential_encryption_jwk -> credential_encryption_jwk[Option<JWK>],
            set_credential_response_encryption_alg -> credential_response_encryption_alg[Option<JA>],
            set_credential_response_encryption_enc -> credential_response_encryption_enc[Option<JE>],
        }
    ];
}

pub struct RequestBuilder<CR, JT, JE, JA>
where
    CR: CredentialRequestProfile,
    JT: JsonWebKeyType,
    JE: JweContentEncryptionAlgorithm<JT>,
    JA: JweKeyManagementAlgorithm,
{
    body: Request<CR, JT, JE, JA>,
    url: CredentialUrl,
    access_token: AccessToken,
}

impl<CR, JT, JE, JA> RequestBuilder<CR, JT, JE, JA>
where
    CR: CredentialRequestProfile,
    JT: JsonWebKeyType,
    JE: JweContentEncryptionAlgorithm<JT>,
    JA: JweKeyManagementAlgorithm,
{
    pub(crate) fn new(
        body: Request<CR, JT, JE, JA>,
        url: CredentialUrl,
        access_token: AccessToken,
    ) -> Self {
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
            set_credential_encryption_jwk -> credential_encryption_jwk[Option<JWK>],
            set_credential_response_encryption_alg -> credential_response_encryption_alg[Option<JA>],
            set_credential_response_encryption_enc -> credential_response_encryption_enc[Option<JE>],
        }
    ];

    pub fn request<HC, RE>(
        self,
        http_client: HC,
    ) -> Result<Response<CR::Response>, RequestError<RE>>
    where
        HC: FnOnce(HttpRequest) -> Result<HttpResponse, RE>,
        RE: std::error::Error + 'static,
    {
        http_client(self.prepare_request()?)
            .map_err(RequestError::Request)
            .and_then(|http_response| self.credential_response(http_response))
    }

    pub async fn request_async<C, F, RE>(
        self,
        http_client: C,
    ) -> Result<Response<CR::Response>, RequestError<RE>>
    where
        C: FnOnce(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: std::error::Error + 'static,
    {
        let http_request = self.prepare_request()?;
        let http_response = http_client(http_request)
            .await
            .map_err(RequestError::Request)?;

        self.credential_response(http_response)
    }

    fn prepare_request<RE>(&self) -> Result<HttpRequest, RequestError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        let (auth_header, auth_value) = auth_bearer(&self.access_token);
        Ok(HttpRequest {
            url: self.url.url().clone(),
            method: Method::POST,
            headers: vec![
                (CONTENT_TYPE, HeaderValue::from_static(MIME_TYPE_JSON)),
                (ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON)),
                (auth_header, auth_value),
            ]
            .into_iter()
            .collect(),
            body: serde_json::to_vec(&self.body).map_err(|e| RequestError::Other(e.to_string()))?,
        })
    }

    fn credential_response<RE>(
        self,
        http_response: HttpResponse,
    ) -> Result<Response<CR::Response>, RequestError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        // TODO status 202 if deferred
        if http_response.status_code != StatusCode::OK {
            return Err(RequestError::Response(
                http_response.status_code,
                http_response.body,
                "unexpected HTTP status code".to_string(),
            ));
        }

        match http_response
            .headers
            .get(CONTENT_TYPE)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| HeaderValue::from_static(MIME_TYPE_JSON))
        {
            ref content_type if content_type_has_essence(content_type, MIME_TYPE_JSON) => {
                serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(
                    &http_response.body,
                ))
                .map_err(RequestError::Parse)
            }
            ref content_type => Err(RequestError::Response(
                http_response.status_code,
                http_response.body,
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
    #[error("Failed to verify claims")]
    ClaimsVerification(#[source] ClaimsVerificationError),
    #[error("Failed to parse server response")]
    Parse(#[source] serde_path_to_error::Error<serde_json::Error>),
    #[error("Request failed")]
    Request(#[source] RE),
    #[error("Server returned invalid response: {2}")]
    Response(StatusCode, Vec<u8>, String),
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
        pub self [self] ["credential request value"] {
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
    InvalidRequest,
    InvalidToken,
    UnsupportedCredentialType,
    UnsupportedCredentialFormat,
    InvalidProof,
    InvalidEncryptionParameters,
}
impl ErrorResponseType for ErrorType {}
pub type Error = StandardErrorResponse<ErrorType>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BatchRequest<CR, JT, JE, JA>
where
    CR: CredentialRequestProfile,
    JT: JsonWebKeyType,
    JE: JweContentEncryptionAlgorithm<JT>,
    JA: JweKeyManagementAlgorithm,
{
    #[serde(bound = "CR: CredentialRequestProfile")]
    credential_requests: Vec<Request<CR, JT, JE, JA>>,
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
