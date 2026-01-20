use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{issuer::metadata::CredentialFormatMetadata, types::LanguageTag};

use super::W3cVcFormat;

/// Format configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W3cVcFormatMetadata {
    #[serde(rename = "format")]
    pub id: W3cVcFormat,

    pub credential_definition: W3cVcDefinitionMetadata,
}

impl CredentialFormatMetadata for W3cVcFormatMetadata {
    type Format = W3cVcFormat;

    type SigningAlgorithm = String;

    fn id(&self) -> W3cVcFormat {
        self.id
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W3cVcDefinitionMetadata {
    #[serde(rename = "@context")]
    pub context: Vec<ssi::json_ld::syntax::ContextEntry>,

    pub r#type: Vec<String>,

    #[serde(
        rename = "credentialSubject",
        skip_serializing_if = "IndexMap::is_empty"
    )]
    pub credential_subject: IndexMap<String, W3cVcClaimMetadata>,

    pub order: Option<Vec<String>>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W3cVcClaimMetadata {
    #[serde(default, skip_serializing_if = "crate::util::is_false")]
    pub mandatory: bool,

    pub value_type: Option<String>,

    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub display: Vec<W3cVcClaimDisplay>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W3cVcClaimDisplay {
    pub name: Option<String>,

    pub locale: Option<LanguageTag>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::issuer::metadata::CredentialConfiguration;

    use super::*;

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
        let credential_configuration: CredentialConfiguration<W3cVcFormatMetadata> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_configuration).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
