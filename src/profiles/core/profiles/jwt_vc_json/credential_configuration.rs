use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    profiles::core::profiles::CredentialConfigurationClaim,
    profiles::CredentialConfigurationProfile,
};

use super::{CredentialSubjectClaims, Format};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialConfiguration {
    pub format: Format,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_signing_alg_values_supported: Vec<ssi::jwk::Algorithm>,
    pub credential_definition: CredentialDefinition,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order: Vec<String>,
}

impl CredentialConfigurationProfile for CredentialConfiguration {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinition {
    pub r#type: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        rename = "credentialSubject"
    )]
    pub credential_subject: CredentialSubjectClaims<CredentialConfigurationClaim>,
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::issuer::metadata::CredentialConfiguration;

    #[test]
    fn roundtrip() {
        let expected_json = json!(
            {
                "format": "jwt_vc_json",
                "scope": "UniversityDegree",
                "cryptographic_binding_methods_supported": [
                    "did:example"
                ],
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
                "credential_definition":{
                    "type": [
                        "VerifiableCredential",
                        "UniversityDegreeCredential"
                    ],
                    "credentialSubject": {
                        "given_name": {
                            "display": [
                                {
                                    "name": "Given Name",
                                    "locale": "en-US"
                                }
                            ]
                        },
                        "family_name": {
                            "display": [
                                {
                                    "name": "Surname",
                                    "locale": "en-US"
                                }
                            ]
                        },
                        "degree": {},
                        "gpa": {
                            "mandatory": true,
                            "display": [
                                {
                                    "name": "GPA"
                                }
                            ]
                        }
                    }
                },
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": [
                            "ES256"
                        ]
                    }
                },
                "display": [
                    {
                        "name": "University Credential",
                        "locale": "en-US",
                        "logo": {
                            "uri": "https://university.example.edu/public/logo.png",
                            "alt_text": "a square logo of a university"
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF"
                    }
                ]
            }
        );
        let credential_configuration: CredentialConfiguration<super::CredentialConfiguration> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_configuration).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
