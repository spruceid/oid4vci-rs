use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::request::CredentialRequestParams;

use super::W3cVcFormat;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W3cVcRequestParams {
    pub credential_definition: W3cVcDefinitionRequest,
}

impl CredentialRequestParams for W3cVcRequestParams {
    type Format = W3cVcFormat;
}

#[skip_serializing_none]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct W3cVcDefinitionRequest {
    #[serde(rename = "@context")]
    pub context: Option<Vec<ssi::json_ld::syntax::ContextEntry>>,

    pub r#type: Option<Vec<String>>,

    #[serde(
        rename = "credentialSubject",
        skip_serializing_if = "IndexMap::is_empty"
    )]
    pub credential_subject: IndexMap<String, W3cClaimRequest>,
}

impl W3cVcDefinitionRequest {
    pub fn with_context(mut self, context: ssi::json_ld::syntax::ContextEntry) -> Self {
        self.context.get_or_insert_default().push(context);
        self
    }

    pub fn with_contexts(
        mut self,
        contexts: impl IntoIterator<Item = ssi::json_ld::syntax::ContextEntry>,
    ) -> Self {
        self.context.get_or_insert_default().extend(contexts);
        self
    }

    pub fn with_type(mut self, ty: impl Into<String>) -> Self {
        self.r#type.get_or_insert_default().push(ty.into());
        self
    }

    pub fn with_types(mut self, types: impl IntoIterator<Item = String>) -> Self {
        self.r#type.get_or_insert_default().extend(types);
        self
    }

    pub fn with_claim(mut self, id: impl Into<String>, spec: W3cClaimRequest) -> Self {
        self.credential_subject.insert(id.into(), spec);
        self
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W3cClaimRequest {
    /// Indicate to the Issuer that it only accepts Credential(s) issued with
    /// the given claim.
    #[serde(default, skip_serializing_if = "crate::util::is_false")]
    pub mandatory: bool,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::request::CredentialRequest;

    use super::*;

    #[test]
    fn roundtrip_with_format() {
        let expected_json = json!(
            {
                "format": "jwt_vc_json",
                "credential_definition": {
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://www.w3.org/2018/credentials/examples/v1"
                    ],
                    "type": [
                        "VerifiableCredential",
                        "UniversityDegreeCredential"
                    ],
                    "credentialSubject": {
                        "given_name": {},
                        "family_name": {},
                        "degree": {}
                    }
                },
                "proof": {
                    "proof_type": "jwt",
                    "jwt":"eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
                }
            }
        );

        let credential_request: CredentialRequest<W3cVcRequestParams> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_request).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped);
    }

    #[test]
    fn roundtrip() {
        let expected_json = json!(
            {
                "credential_identifier": "UniversityDegreeCredential",
                "credential_definition": {
                    "credentialSubject": {
                        "given_name": {},
                        "family_name": {},
                        "degree": {}
                    }
                },
                "proof": {
                    "proof_type": "jwt",
                    "jwt":"eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
                }
            }
        );

        let credential_request: CredentialRequest<W3cVcRequestParams> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_request).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped);
    }
}
