use openidconnect::{ErrorResponseType, Nonce};
use serde::{Deserialize, Serialize};
use ssi::jwk::JWK;

use crate::{
    credential_profiles::{CredentialRequestProfile, CredentialResponseProfile},
    proof_of_possession::Proof,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialRequest<CR>
where
    CR: CredentialRequestProfile,
{
    #[serde(flatten, bound = "CR: CredentialRequestProfile")]
    addition_profile_fields: CR,
    proof: Option<Proof>,
    credential_encryption_jwk: Option<JWK>,
    credential_response_encryption_alg: Option<String>, // TODO
    credential_response_encryption_enc: Option<String>, // TODO
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponse<CR>
where
    CR: CredentialResponseProfile,
{
    #[serde(flatten, bound = "CR: CredentialResponseProfile")]
    addition_profile_fields: CredentialResponseEnum<CR>,
    c_nonce: Option<Nonce>,
    c_nonce_expires_in: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CredentialResponseEnum<CR>
where
    CR: CredentialResponseProfile,
{
    #[serde(bound = "CR: CredentialResponseProfile")]
    Immedate(CR),
    Deferred {
        transaction_id: Option<String>, // must be present if credential is None (is the profile)
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialResponseError {
    InvalidRequest,
    InvalidToken,
    UnsupportedCredentialType,
    UnsupportedCredentialFormat,
    InvalidProof,
    InvalidEncryptionParameters,
}
impl ErrorResponseType for CredentialResponseError {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BatchCredentialRequest<CR>
where
    CR: CredentialRequestProfile,
{
    #[serde(bound = "CR: CredentialRequestProfile")]
    credential_requests: Vec<CredentialRequest<CR>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BatchCredentialResponse<CR>
where
    CR: CredentialResponseProfile,
{
    #[serde(bound = "CR: CredentialResponseProfile")]
    credential_responses: Vec<CredentialResponseEnum<CR>>,
    c_nonce: Option<Nonce>,
    c_nonce_expires_in: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DeferredCredentialRequest {
    transaction_id: String,
}

#[cfg(test)]
mod test {
    use openidconnect::StandardErrorResponse;
    use serde_json::json;

    use crate::credential_profiles::{CoreProfilesRequest, CoreProfilesResponse};

    use super::*;

    #[test]
    fn example_credential_request_object() {
        let _: CredentialRequest<CoreProfilesRequest> = serde_json::from_value(json!({
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
        let _: CredentialResponse<CoreProfilesResponse> = serde_json::from_value(json!({
            "format": "jwt_vc_json",
            "credential": "LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L",
            "c_nonce": "fGFF7UkhLa",
            "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_deferred_response_object() {
        let _: CredentialResponse<CoreProfilesResponse> = serde_json::from_value(json!({
            "transaction_id": "8xLOxBtZp8",
            "c_nonce": "wlbQc6pCJp",
            "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }

    #[test]
    fn example_error() {
        let _: StandardErrorResponse<CredentialResponseError> = serde_json::from_value(json!({
            "error": "invalid_proof",
            "error_description": "Credential Issuer requires key proof to be bound to a Credential Issuer provided nonce.",
            "c_nonce": "8YE9hCnyV2",
            "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }

    #[test]
    fn example_batch_request() {
        let _: BatchCredentialRequest<CoreProfilesRequest> = serde_json::from_value(json!({
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
        let _: BatchCredentialResponse<CoreProfilesResponse> = serde_json::from_value(json!({
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
        let _: BatchCredentialResponse<CoreProfilesResponse> = serde_json::from_value(json!({
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
        let _: DeferredCredentialRequest = serde_json::from_value(json!({
            "transaction_id":"8xLOxBtZp8"
        }))
        .unwrap();
    }
}
