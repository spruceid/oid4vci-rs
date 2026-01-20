use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{issuer::metadata::CredentialFormatMetadata, types::LanguageTag};

use super::MsoMdocFormat;

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsoMdocFormatMetadata {
    #[serde(rename = "format")]
    pub id: MsoMdocFormat,

    pub doctype: String,

    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub claims: IndexMap<String, IndexMap<String, MsoMdocClaimMetadata>>,

    pub order: Option<Vec<String>>,
}

impl CredentialFormatMetadata for MsoMdocFormatMetadata {
    type Format = MsoMdocFormat;

    type SigningAlgorithm = String;

    fn id(&self) -> Self::Format {
        self.id
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsoMdocClaimMetadata {
    #[serde(default, skip_serializing_if = "crate::util::is_false")]
    pub mandatory: bool,

    pub value_type: Option<String>,

    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub display: Vec<MsoMdocClaimDisplay>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsoMdocClaimDisplay {
    pub name: Option<String>,

    pub locale: Option<LanguageTag>,
}

#[cfg(test)]
mod tests {
    use crate::issuer::metadata::CredentialConfiguration;

    use super::*;

    #[test]
    fn roundtrip() {
        let expected_json = serde_json::json!(
            {
                "format": "mso_mdoc",
                "doctype": "org.iso.18013.5.1.mDL",
                "cryptographic_binding_methods_supported": [
                    "cose_key"
                ],
                "credential_signing_alg_values_supported": [
                    "ES256", "ES384", "ES512"
                ],
                "display": [
                    {
                        "name": "Mobile Driving License",
                        "locale": "en-US",
                        "logo": {
                            "uri": "https://state.example.org/public/mdl.png",
                            "alt_text": "state mobile driving license"
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF"
                    },
                    {
                        "name": "モバイル運転免許証",
                        "locale": "ja-JP",
                        "logo": {
                            "uri": "https://state.example.org/public/mdl.png",
                            "alt_text": "米国州発行のモバイル運転免許証"
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF"
                    }
                ],
                "claims": {
                    "org.iso.18013.5.1": {
                        "given_name": {
                            "display": [
                                {
                                    "name": "Given Name",
                                    "locale": "en-US"
                                },
                                {
                                    "name": "名前",
                                    "locale": "ja-JP"
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
                        "birth_date": {
                            "mandatory": true
                        }
                    },
                    "org.iso.18013.5.1.aamva": {
                        "organ_donor": {}
                    }
                }
            }
        );
        let credential_configuration: CredentialConfiguration<MsoMdocFormatMetadata> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_configuration).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
