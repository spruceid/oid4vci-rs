use isomdl::definitions::device_request::DocType;
use serde::{Deserialize, Serialize};

use crate::{
    core::profiles::CredentialConfigurationClaim, profiles::CredentialConfigurationProfile,
};

use super::{Claims, Format};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialConfiguration {
    format: Format,
    // TODO: Enumerate possible COSE algs
    doctype: DocType,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    credential_signing_alg_values_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Claims::is_empty")]
    claims: Claims<CredentialConfigurationClaim>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    order: Vec<String>,
}

impl CredentialConfiguration {
    pub fn new(doctype: DocType) -> Self {
        Self {
            format: Format::MsoMdoc,
            doctype,
            credential_signing_alg_values_supported: Vec::new(),
            claims: Default::default(),
            order: Vec::new(),
        }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL metadata value"] {
            set_doctype -> doctype[DocType],
            set_credential_signing_alg_values_supported -> credential_signing_alg_values_supported[Vec<String>],
            set_claims -> claims[Claims<CredentialConfigurationClaim>],
            set_order -> order[Vec<String>],
        }
    ];
}

impl CredentialConfigurationProfile for CredentialConfiguration {}

#[cfg(test)]
mod test {
    use crate::metadata::credential_issuer::CredentialConfiguration;

    #[test]
    fn roundtrip() {
        let expected_json = serde_json::json!(
            {
                "$key$": "org.iso.18013.5.1.mDL",
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
        let credential_configuration: CredentialConfiguration<super::CredentialConfiguration> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_configuration).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
