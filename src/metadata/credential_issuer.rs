use anyhow::bail;
use oauth2::Scope;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, KeyValueMap};

use crate::{
    credential_response_encryption::CredentialResponseEncryptionMetadata,
    profiles::CredentialConfigurationProfile,
    proof_of_possession::KeyProofTypesSupported,
    types::{
        BatchCredentialUrl, CredentialConfigurationId, CredentialUrl, DeferredCredentialUrl,
        IssuerUrl, LanguageTag, LogoUri, NotificationUrl,
    },
};

use super::MetadataDiscovery;

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialIssuerMetadata<CM>
where
    CM: CredentialConfigurationProfile,
{
    credential_issuer: IssuerUrl,
    authorization_servers: Option<Vec<IssuerUrl>>,
    credential_endpoint: CredentialUrl,
    batch_credential_endpoint: Option<BatchCredentialUrl>,
    deferred_credential_endpoint: Option<DeferredCredentialUrl>,
    notification_endpoint: Option<NotificationUrl>,
    credential_response_encryption: Option<CredentialResponseEncryptionMetadata>,
    credential_identifiers_supported: Option<bool>,
    signed_metadata: Option<String>,
    display: Option<Vec<CredentialIssuerMetadataDisplay>>,
    #[serde(default = "Vec::new", bound = "CM: CredentialConfigurationProfile")]
    #[serde_as(as = "KeyValueMap<_>")]
    credential_configurations_supported: Vec<CredentialConfiguration<CM>>,
}

impl<CM> MetadataDiscovery for CredentialIssuerMetadata<CM>
where
    CM: CredentialConfigurationProfile,
{
    const METADATA_URL_SUFFIX: &'static str = ".well-known/openid-credential-issuer";

    fn validate(&self, issuer: &IssuerUrl) -> anyhow::Result<()> {
        if self.credential_issuer() != issuer {
            bail!(
                "unexpected issuer URI `{}` (expected `{}`)",
                self.credential_issuer().as_str(),
                issuer.as_str()
            )
        }
        Ok(())
    }
}

impl<CM> CredentialIssuerMetadata<CM>
where
    CM: CredentialConfigurationProfile,
{
    pub fn new(credential_issuer: IssuerUrl, credential_endpoint: CredentialUrl) -> Self {
        Self {
            credential_issuer,
            authorization_servers: None,
            credential_endpoint,
            batch_credential_endpoint: None,
            deferred_credential_endpoint: None,
            notification_endpoint: None,
            credential_response_encryption: None,
            credential_identifiers_supported: None,
            signed_metadata: None,
            display: None,
            credential_configurations_supported: vec![],
        }
    }

    field_getters_setters![
        pub self [self] ["credential issuer metadata value"] {
            set_credential_issuer -> credential_issuer[IssuerUrl],
            set_authorization_servers -> authorization_servers[Option<Vec<IssuerUrl>>],
            set_credential_endpoint -> credential_endpoint[CredentialUrl],
            set_batch_credential_endpoint -> batch_credential_endpoint[Option<BatchCredentialUrl>],
            set_deferred_credential_endpoint -> deferred_credential_endpoint[Option<DeferredCredentialUrl>],
            set_notification_endpoint -> notification_endpoint[Option<NotificationUrl>],
            set_credential_response_encryption -> credential_response_encryption[Option<CredentialResponseEncryptionMetadata>],
            set_credential_identifiers_supported -> credential_identifiers_supported[Option<bool>],
            set_signed_metadata -> signed_metadata[Option<String>],
            set_display -> display[Option<Vec<CredentialIssuerMetadataDisplay>>],
            set_credential_configurations_supported -> credential_configurations_supported[Vec<CredentialConfiguration<CM>>],
        }
    ];
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialIssuerMetadataDisplay {
    name: Option<String>,
    locale: Option<LanguageTag>,
    logo: Option<MetadataDisplayLogo>,
}

impl CredentialIssuerMetadataDisplay {
    pub fn new(
        name: Option<String>,
        locale: Option<LanguageTag>,
        logo: Option<MetadataDisplayLogo>,
    ) -> Self {
        Self { name, locale, logo }
    }

    field_getters_setters![
        pub self [self] ["metadata background image value"] {
            set_name -> name[Option<String>],
            set_locale -> locale[Option<LanguageTag>],
            set_logo -> logo[Option<MetadataDisplayLogo>],
        }
    ];
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MetadataDisplayLogo {
    uri: LogoUri,
    alt_text: Option<String>,
}

impl MetadataDisplayLogo {
    pub fn new(uri: LogoUri, alt_text: Option<String>) -> Self {
        Self { uri, alt_text }
    }

    field_getters_setters![
        pub self [self] ["metadata display logo value"] {
            set_url -> uri[LogoUri],
            set_alt_text -> alt_text[Option<String>],
        }
    ];
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialConfiguration<CM>
where
    CM: CredentialConfigurationProfile,
{
    #[serde(rename = "$key$")]
    name: CredentialConfigurationId,
    scope: Option<Scope>,
    cryptographic_binding_methods_supported: Option<Vec<CryptographicBindingMethod>>,
    #[serde_as(as = "Option<KeyValueMap<_>>")]
    proof_types_supported: Option<Vec<KeyProofTypesSupported>>,
    display: Option<Vec<CredentialMetadataDisplay>>,
    #[serde(bound = "CM: CredentialConfigurationProfile")]
    #[serde(flatten)]
    profile_specific_fields: CM,
}

impl<CM> CredentialConfiguration<CM>
where
    CM: CredentialConfigurationProfile,
{
    pub fn new(name: CredentialConfigurationId, profile_specific_fields: CM) -> Self {
        Self {
            name,
            scope: None,
            cryptographic_binding_methods_supported: None,
            proof_types_supported: None,
            display: None,
            profile_specific_fields,
        }
    }

    field_getters_setters![
        pub self [self] ["credential metadata value"] {
            set_name -> name[CredentialConfigurationId],
            set_scope -> scope[Option<Scope>],
            set_cryptographic_binding_methods_supported -> cryptographic_binding_methods_supported[Option<Vec<CryptographicBindingMethod>>],
            set_proof_types_supported -> proof_types_supported[Option<Vec<KeyProofTypesSupported>>],
            set_display -> display[Option<Vec<CredentialMetadataDisplay>>],
            set_profile_specific_fields -> profile_specific_fields[CM],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CryptographicBindingMethod {
    #[serde(rename = "jwk")]
    Jwk,
    #[serde(rename = "cose_key")]
    Cose,
    #[serde(rename = "mso")]
    MSO,
    #[serde(rename = "did:")]
    Did,
    #[cfg(test)]
    #[serde(rename = "did:example")]
    DidExample,
    #[serde(untagged)]
    Extension(String),
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialMetadataDisplay {
    name: String,
    locale: Option<LanguageTag>,
    logo: Option<MetadataDisplayLogo>,
    description: Option<String>,
    background_color: Option<String>,
    background_image: Option<MetadataBackgroundImage>,
    text_color: Option<String>,
}

impl CredentialMetadataDisplay {
    pub fn new(
        name: String,
        locale: Option<LanguageTag>,
        logo: Option<MetadataDisplayLogo>,
        description: Option<String>,
        background_color: Option<String>,
        background_image: Option<MetadataBackgroundImage>,
        text_color: Option<String>,
    ) -> Self {
        Self {
            name,
            locale,
            logo,
            description,
            background_color,
            background_image,
            text_color,
        }
    }

    field_getters_setters![
        pub self [self] ["credential metadata display value"] {
            set_name -> name[String],
            set_locale -> locale[Option<LanguageTag>],
            set_logo -> logo[Option<MetadataDisplayLogo>],
            set_description -> description[Option<String>],
            set_background_color -> background_color[Option<String>],
            set_background_image -> background_image[Option<MetadataBackgroundImage>],
            set_text_color -> text_color[Option<String>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MetadataBackgroundImage {
    uri: LogoUri,
}

impl MetadataBackgroundImage {
    pub fn new(uri: LogoUri) -> Self {
        Self { uri }
    }

    field_getters_setters![
        pub self [self] ["metadata background image value"] {
            set_uri -> uri[LogoUri],
        }
    ];
}

#[cfg(test)]
mod test {
    use crate::core::profiles::CoreProfilesCredentialConfiguration;
    use serde_json::json;

    use super::*;

    #[test]
    fn example_credential_issuer_metadata() {
        let _: CredentialIssuerMetadata<
            CoreProfilesCredentialConfiguration,
        > = serde_json::from_value(json!({
            "credential_issuer": "https://credential-issuer.example.com",
            "authorization_servers": [ "https://server.example.com" ],
            "credential_endpoint": "https://credential-issuer.example.com",
            "batch_credential_endpoint": "https://credential-issuer.example.com/batch_credential",
            "deferred_credential_endpoint": "https://credential-issuer.example.com/deferred_credential",
            "credential_response_encryption": {
                "alg_values_supported" : [
                    "ECDH-ES"
                ],
                "enc_values_supported" : [
                    "A128GCM"
                ],
                "encryption_required": false
            },
            "display": [
                {
                    "name": "Example University",
                    "locale": "en-US"
                },
                {
                    "name": "Example Université",
                    "locale": "fr-FR"
                }
            ],
            "credential_configurations_supported": {
                "UniversityDegreeCredential": {
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
                            "background_image": {
                                "uri": "https://university.example.edu/public/background-image.png"
                            },
                            "text_color": "#FFFFFF"
                        }
                    ]
                }
            }
        })).unwrap();
    }

    #[test]
    fn example_credential_metadata_jwt() {
        let _: CredentialConfiguration<CoreProfilesCredentialConfiguration> =
            serde_json::from_value(json!({
                "$key$": "name", // purely for test reason, you cannot really deserialize CredentialMetadata on its own
                "format": "jwt_vc_json",
                "id": "UniversityDegree_JWT",
                "cryptographic_binding_methods_supported": [
                    "did:example"
                ],
                "credential_signing_alg_values_supported": [
                    "ES256K"
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
                            "uri": "https://exampleuniversity.com/public/logo.png",
                            "alt_text": "a square logo of a university"
                        },
                        "background_color": "#12107c",
                        "background_image": {
                            "uri": "https://university.example.edu/public/background-image.png"
                        },
                        "text_color": "#FFFFFF"
                    }
                ]
            }))
            .unwrap();
    }

    #[test]
    fn example_credential_metadata_ldp() {
        let _: CredentialConfiguration<CoreProfilesCredentialConfiguration> =
            serde_json::from_value(json!({
                "$key$": "name", // purely for test reason, you cannot really deserialize CredentialMetadata on its own
                "format": "ldp_vc",
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ],
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
                            "uri": "https://exampleuniversity.com/public/logo.png",
                            "alt_text": "a square logo of a university"
                        },
                        "background_color": "#12107c",
                        "background_image": {
                            "uri": "https://university.example.edu/public/background-image.png"
                        },
                        "text_color": "#FFFFFF"
                    }
                ]
            }))
            .unwrap();
    }

    #[test]
    fn example_credential_metadata_isomdl() {
        let _: CredentialConfiguration<CoreProfilesCredentialConfiguration> =
            serde_json::from_value(json!({
                "$key$": "name", // purely for test reason, you cannot really deserialize CredentialMetadata on its own
                "format": "mso_mdoc",
                "doctype": "org.iso.18013.5.1.mDL",
                "cryptographic_binding_methods_supported": [
                    "mso"
                ],
                "credential_signing_alg_values_supported": [
                    "ES256", "ES384", "ES512"
                ],
                "display": [
                    {
                        "name": "Mobile Driving License",
                        "locale": "en-US",
                        "logo": {
                            "uri": "https://examplestate.com/public/mdl.png",
                            "alt_text": "a square figure of a mobile driving license"
                        },
                        "background_color": "#12107c",
                        "background_image": {
                            "uri": "https://examplestate.com/public/background-image.png"
                        },
                        "text_color": "#FFFFFF"
                    },
                    {
                        "name": "在籍証明書",
                        "locale": "ja-JP",
                        "logo": {
                            "uri": "https://examplestate.com/public/mdl.png",
                            "alt_text": "大学のロゴ"
                        },
                        "background_color": "#12107c",
                        "background_image": {
                            "uri": "https://examplestate.com/public/background-image.png"
                        },
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
                        "birth_date": {}
                    },
                    "org.iso.18013.5.1.aamva": {
                        "organ_donor": {}
                    }
                }
            }))
            .unwrap();
    }
}
