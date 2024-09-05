use serde::{Deserialize, Serialize};

use crate::profiles::CredentialRequestProfile;

use super::{authorization_detail::CredentialDefinition, CredentialResponse, Format};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialRequestWithFormat {
    format: Format,
    credential_definition: CredentialDefinition,
}

impl CredentialRequestWithFormat {
    pub fn new(credential_definition: CredentialDefinition) -> Self {
        Self {
            format: Format::default(),
            credential_definition,
        }
    }
    field_getters_setters![
        pub self [self] ["JWT VC request value"] {
            set_credential_definition -> credential_definition[CredentialDefinition],
        }
    ];
}

impl CredentialRequestProfile for CredentialRequestWithFormat {
    type Response = CredentialResponse;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialRequest {}

impl CredentialRequest {
    pub fn new() -> Self {
        Self {}
    }
}

impl CredentialRequestProfile for CredentialRequest {
    type Response = CredentialResponse;
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::{core::profiles::CoreProfilesCredentialRequest, credential::Request};

    #[test]
    fn roundtrip_with_format() {
        let expected_json = json!(
            {
                "format": "jwt_vc_json",
                "credential_definition": {
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

        let credential_request: Request<super::CredentialRequestWithFormat> =
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

        let credential_request: Request<CoreProfilesCredentialRequest> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_request).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped);
    }
}
