use std::fmt::Debug;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::profiles::CredentialRequestProfile;

use super::{authorization_detail::CredentialDefinition, CredentialResponse};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialRequestWithFormat<F> {
    format: F,
    credential_definition: CredentialDefinition,
}

impl<F> CredentialRequestWithFormat<F> {
    pub fn new(credential_definition: CredentialDefinition) -> Self
    where
        F: Default,
    {
        Self {
            format: F::default(),
            credential_definition,
        }
    }
    field_getters_setters![
        pub self [self] ["request value"] {
            set_credential_definition -> credential_definition[CredentialDefinition],
        }
    ];
}

impl<F> CredentialRequestProfile for CredentialRequestWithFormat<F>
where
    F: DeserializeOwned + Serialize + Debug + Clone,
{
    type Response = CredentialResponse;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialRequest {}

impl Default for CredentialRequest {
    fn default() -> Self {
        Self::new()
    }
}

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

    use crate::{
        core::profiles::{ldp_vc::Format, CoreProfilesCredentialRequest},
        credential::Request,
    };

    #[test]
    fn roundtrip_with_format() {
        let expected_json = json!(
            {
                "format": "ldp_vc",
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
                      "degree": {
                         "type": {}
                      }
                   }
                },
                "proof": {
                   "proof_type": "ldp_vp",
                   "ldp_vp": {
                      "@context": [
                         "https://www.w3.org/ns/credentials/v2",
                         "https://www.w3.org/ns/credentials/examples/v2"
                      ],
                      "type": [
                         "VerifiablePresentation"
                      ],
                      "holder": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
                      "proof": [
                         {
                            "type": "DataIntegrityProof",
                            "cryptosuite": "eddsa-2022",
                            "proofPurpose": "authentication",
                            "verificationMethod": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro#z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
                            "created": "2023-03-01T14:56:29.280619Z",
                            "challenge": "82d4cb36-11f6-4273-b9c6-df1ac0ff17e9",
                            "domain": "did:web:audience.company.com",
                            "proofValue": "z5hrbHzZiqXHNpLq6i7zePEUcUzEbZKmWfNQzXcUXUrqF7bykQ7ACiWFyZdT2HcptF1zd1t7NhfQSdqrbPEjZceg7"
                         }
                      ]
                   }
                }
            }
        );

        let credential_request: Request<super::CredentialRequestWithFormat<Format>> =
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
                      "degree": {
                         "type": {}
                      }
                   }
                },
                "proof": {
                   "proof_type": "ldp_vp",
                   "ldp_vp": {
                      "@context": [
                         "https://www.w3.org/ns/credentials/v2",
                         "https://www.w3.org/ns/credentials/examples/v2"
                      ],
                      "type": [
                         "VerifiablePresentation"
                      ],
                      "holder": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
                      "proof": [
                         {
                            "type": "DataIntegrityProof",
                            "cryptosuite": "eddsa-2022",
                            "proofPurpose": "authentication",
                            "verificationMethod": "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro#z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
                            "created": "2023-03-01T14:56:29.280619Z",
                            "challenge": "82d4cb36-11f6-4273-b9c6-df1ac0ff17e9",
                            "domain": "did:web:audience.company.com",
                            "proofValue": "z5hrbHzZiqXHNpLq6i7zePEUcUzEbZKmWfNQzXcUXUrqF7bykQ7ACiWFyZdT2HcptF1zd1t7NhfQSdqrbPEjZceg7"
                         }
                      ]
                   }
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
