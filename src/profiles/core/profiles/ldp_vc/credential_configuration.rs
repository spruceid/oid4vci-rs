use std::collections::HashMap;
use std::fmt::Debug;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::{
    profiles::core::profiles::CredentialConfigurationClaim,
    profiles::CredentialConfigurationProfile,
};

use super::CredentialSubjectClaims;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialConfiguration<F> {
    pub format: F,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    // TODO: Enumerate types from LD Suite Registry:
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#appendix-A.1.2.2-1
    pub credential_signing_alg_values_supported: Vec<String>,
    pub credential_definition: CredentialDefinition,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order: Vec<String>,
}

impl<F> CredentialConfigurationProfile for CredentialConfiguration<F> where
    F: DeserializeOwned + Serialize + Debug + Clone
{
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinition {
    #[serde(rename = "@context")]
    pub context: Vec<Value>,
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

    use crate::{
        issuer::metadata::CredentialConfiguration, profiles::core::profiles::ldp_vc::Format,
    };

    #[test]
    fn roundtrip() {
        let expected_json = json!(
            {
                "format": "ldp_vc",
                "cryptographic_binding_methods_supported": [
                    "did:example"
                ],
                "credential_signing_alg_values_supported": [
                    "Ed25519Signature2018"
                ],
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
        let credential_configuration: CredentialConfiguration<
            super::CredentialConfiguration<Format>,
        > = serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
            &serde_json::to_string(&expected_json).unwrap(),
        ))
        .unwrap();

        let roundtripped = serde_json::to_value(credential_configuration).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
