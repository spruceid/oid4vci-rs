use anyhow::bail;
use indexmap::IndexMap;
use iref::{uri_ref, Uri, UriBuf, UriRef};
use oauth2::Scope;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};

use crate::{
    encryption::CredentialResponseEncryptionMetadata,
    profiles::CredentialConfigurationProfile,
    proof_of_possession::KeyProofType,
    types::{
        BatchCredentialUrl, CredentialConfigurationId, CredentialUrl, DeferredCredentialUrl,
        LanguageTag, LogoUri, NotificationUrl,
    },
    util::discoverable::Discoverable,
};

/// Credential Issuer Metadata.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-11.2>
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialIssuerMetadata<CM>
where
    CM: CredentialConfigurationProfile,
{
    /// Credential Issuer's identifier.
    pub credential_issuer: UriBuf,

    /// List of OAuth 2.0 Authorization Server (as defined in [RFC8414]) the
    /// Credential Issuer relies on for authorization.
    ///
    /// [RFC8414]: <https://www.rfc-editor.org/info/rfc8414>
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub authorization_servers: Vec<UriBuf>,

    /// URL of the Credential Issuer's Credential Endpoint.
    ///
    /// This URL *must* use the `https` scheme and *may* contain port, path, and
    /// query parameter components.
    pub credential_endpoint: CredentialUrl,

    /// DEPRECATED in version 1.0
    pub batch_credential_endpoint: Option<BatchCredentialUrl>,

    /// URL of the Credential Issuer's Deferred Credential Endpoint.
    ///
    /// This URL *must* use the `https` scheme and *may* contain port, path, and
    /// query parameter components.
    ///
    /// If omitted, the Credential Issuer does not support the Deferred
    /// Credential Endpoint.
    pub deferred_credential_endpoint: Option<DeferredCredentialUrl>,

    /// URL of the Credential Issuer's Notification Endpoint.
    ///
    /// This URL *must* use the `https` scheme and *may* contain port, path, and
    /// query parameter components.
    ///
    /// If omitted, the Credential Issuer does not support the Notification
    /// Endpoint.
    pub notification_endpoint: Option<NotificationUrl>,

    /// Information about whether the Credential Issuer supports encryption of
    /// the Credential and Batch Credential Response on top of TLS.
    pub credential_response_encryption: Option<CredentialResponseEncryptionMetadata>,

    /// DEPRECATED in version 1.0
    pub credential_identifiers_supported: Option<bool>,

    /// Credential Issuer Metadata signed as a JWT.
    pub signed_metadata: Option<String>, // TODO turn that into an actual `JwsString`.

    /// Credential Issuer display properties.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub display: Vec<CredentialIssuerMetadataDisplay>,

    /// Specifics of the Credential that the Credential Issuer supports issuance
    /// of.
    ///
    /// List of name/value pairs, where each name is a unique identifier of the
    /// supported Credential being described.
    #[serde(bound = "CM: CredentialConfigurationProfile")]
    pub credential_configurations_supported:
        IndexMap<CredentialConfigurationId, CredentialConfiguration<CM>>,
}

impl<CM> Discoverable for CredentialIssuerMetadata<CM>
where
    CM: CredentialConfigurationProfile,
{
    const WELL_KNOWN_URI_REF: &UriRef = uri_ref!(".well-known/openid-credential-issuer");

    fn validate(&self, issuer: &Uri) -> anyhow::Result<()> {
        if self.credential_issuer != issuer {
            bail!(
                "unexpected issuer URI `{}` (expected `{}`)",
                self.credential_issuer,
                issuer
            )
        }
        Ok(())
    }
}

impl<CM> CredentialIssuerMetadata<CM>
where
    CM: CredentialConfigurationProfile,
{
    pub fn new(credential_issuer: UriBuf, credential_endpoint: CredentialUrl) -> Self {
        Self {
            credential_issuer,
            authorization_servers: Vec::new(),
            credential_endpoint,
            batch_credential_endpoint: None,
            deferred_credential_endpoint: None,
            notification_endpoint: None,
            credential_response_encryption: None,
            credential_identifiers_supported: None,
            signed_metadata: None,
            display: Vec::new(),
            credential_configurations_supported: IndexMap::new(),
        }
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialIssuerMetadataDisplay {
    pub name: Option<String>,
    pub locale: Option<LanguageTag>,
    pub logo: Option<MetadataDisplayLogo>,
}

impl CredentialIssuerMetadataDisplay {
    pub fn new(
        name: Option<String>,
        locale: Option<LanguageTag>,
        logo: Option<MetadataDisplayLogo>,
    ) -> Self {
        Self { name, locale, logo }
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MetadataDisplayLogo {
    pub uri: LogoUri,
    pub alt_text: Option<String>,
}

impl MetadataDisplayLogo {
    pub fn new(uri: LogoUri, alt_text: Option<String>) -> Self {
        Self { uri, alt_text }
    }
}

/// Credential Issuer Metadata `credential_configurations_supported` parameter
/// value.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-11.2.3>
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialConfiguration<CM>
where
    CM: CredentialConfigurationProfile,
{
    /// TODO where is the required `format` parameter?

    /// String identifying the scope value that this Credential Issuer supports
    /// for this particular Credential.
    ///
    /// The value can be the same across multiple
    /// [`CredentialConfiguration`]s.
    pub scope: Option<Scope>,

    /// TODO missing optional `credential_signing_alg_values_supported` parameter?

    /// Case sensitive strings that identify the representation of the
    /// cryptographic key material that the issued Credential is bound to.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub cryptographic_binding_methods_supported: Vec<CryptographicBindingMethod>,

    /// Specifics of the key proof(s) that the Credential Issuer supports.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub proof_types_supported: IndexMap<KeyProofType, KeyProofTypesSupported>,

    /// Display properties of the supported Credential for different languages.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub display: Vec<CredentialMetadataDisplay>,

    /// Profile-specific fields.
    #[serde(bound = "CM: CredentialConfigurationProfile")]
    #[serde(flatten)]
    pub profile_specific_fields: CM,
}

impl<CM> CredentialConfiguration<CM>
where
    CM: CredentialConfigurationProfile,
{
    pub fn new(profile_specific_fields: CM) -> Self {
        Self {
            scope: None,
            cryptographic_binding_methods_supported: Vec::new(),
            proof_types_supported: IndexMap::new(),
            display: Vec::new(),
            profile_specific_fields,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct KeyProofTypesSupported {
    pub proof_signing_alg_values_supported: Vec<ssi::jwk::Algorithm>,
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
    pub name: String,
    pub locale: Option<LanguageTag>,
    pub logo: Option<MetadataDisplayLogo>,
    pub description: Option<String>,
    pub background_color: Option<String>,
    pub background_image: Option<MetadataBackgroundImage>,
    pub text_color: Option<String>,
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
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MetadataBackgroundImage {
    pub uri: LogoUri,
}

impl MetadataBackgroundImage {
    pub fn new(uri: LogoUri) -> Self {
        Self { uri }
    }
}

#[cfg(test)]
mod test {
    use crate::profiles::core::profiles::CoreProfilesCredentialConfiguration;
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
