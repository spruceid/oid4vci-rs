use openidconnect::{
    core::{
        CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
        CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
        CoreSubjectIdentifierType,
    },
    AdditionalProviderMetadata, IssuerUrl, LanguageTag, LogoUrl, ProviderMetadata, Scope,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};

use crate::{
    credential_profiles::CredentialMetadataProfile, field_getters, field_getters_setters,
    field_setters, proof_of_possession::KeyProofType,
};

pub use crate::types::{BatchCredentialUrl, CredentialUrl, DeferredCredentialUrl};

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IssuerMetadata<CM>
where
    CM: CredentialMetadataProfile,
{
    credential_issuer: IssuerUrl,
    authorization_server: Option<IssuerUrl>, // Not sure this is the right type
    credential_endpoint: CredentialUrl,
    batch_credential_endpoint: Option<BatchCredentialUrl>,
    deferred_credential_endpoint: Option<DeferredCredentialUrl>,
    credential_response_encryption_alg_values_supported: Option<Vec<String>>, // TODO
    credential_response_encryption_enc_values_supported: Option<Vec<String>>, // TODO
    require_credential_response_encryption: Option<bool>,
    #[serde(bound = "CM: CredentialMetadataProfile")]
    credentials_supported: Vec<CredentialMetadata<CM>>,
    display: Option<IssuerMetadataDisplay>,
}

impl<CM> IssuerMetadata<CM>
where
    CM: CredentialMetadataProfile,
{
    pub fn new(
        credential_issuer: IssuerUrl,
        credential_endpoint: CredentialUrl,
        credentials_supported: Vec<CredentialMetadata<CM>>,
    ) -> Self {
        Self {
            credential_issuer,
            authorization_server: None,
            credential_endpoint,
            batch_credential_endpoint: None,
            deferred_credential_endpoint: None,
            credential_response_encryption_alg_values_supported: None,
            credential_response_encryption_enc_values_supported: None,
            require_credential_response_encryption: None,
            credentials_supported,
            display: None,
        }
    }

    field_getters_setters![
        pub self [self] ["issuer metadata value"] {
            set_credential_issuer -> credential_issuer[IssuerUrl],
            set_authorization_server -> authorization_server[Option<IssuerUrl>],
            set_credential_endpoint -> credential_endpoint[CredentialUrl],
            set_batch_credential_endpoint -> batch_credential_endpoint[Option<BatchCredentialUrl>],
            set_deferred_credential_endpoint -> deferred_credential_endpoint[Option<DeferredCredentialUrl>],
            set_credential_response_encryption_alg_values_supported -> credential_response_encryption_alg_values_supported[Option<Vec<String>>],
            set_credential_response_encryption_enc_values_supported -> credential_response_encryption_enc_values_supported[Option<Vec<String>>],
            set_require_credential_response_encryption -> require_credential_response_encryption[Option<bool>],
            set_credentials_supported -> credentials_supported[Vec<CredentialMetadata<CM>>],
            set_display -> display[Option<IssuerMetadataDisplay>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IssuerMetadataDisplay {
    name: Option<String>,
    locale: Option<LanguageTag>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialMetadata<CM>
where
    CM: CredentialMetadataProfile,
{
    scope: Option<Scope>,
    cryptographic_binding_methods_supported: Option<Vec<CryptographicBindingMethod>>,
    proof_types_supported: Option<Vec<KeyProofType>>,
    display: Option<Vec<CredentialMetadataDisplay>>,
    #[serde(bound = "CM: CredentialMetadataProfile")]
    #[serde(flatten)]
    additional_fields: CM,
}

impl<CM> CredentialMetadata<CM>
where
    CM: CredentialMetadataProfile,
{
    pub fn new(additional_fields: CM) -> Self {
        Self {
            scope: None,
            cryptographic_binding_methods_supported: None,
            proof_types_supported: None,
            display: None,
            additional_fields,
        }
    }

    field_getters_setters![
        pub self [self] ["credential metadata value"] {
            set_scope -> scope[Option<Scope>],
            set_cryptographic_binding_methods_supported -> cryptographic_binding_methods_supported[Option<Vec<CryptographicBindingMethod>>],
            set_proof_types_suuported -> proof_types_supported[Option<Vec<KeyProofType>>],
            set_display -> display[Option<Vec<CredentialMetadataDisplay>>],
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
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialMetadataDisplay {
    name: String,
    locale: Option<LanguageTag>,
    logo: Option<CredentialMetadataDisplayLogo>,
    description: Option<String>,
    background_color: Option<String>,
    text_color: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialMetadataDisplayLogo {
    url: Option<LogoUrl>,
    alt_text: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct AdditionalOAuthMetadata {
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pre_authorized_grant_anonymous_access_supported: Option<bool>,
}
impl AdditionalProviderMetadata for AdditionalOAuthMetadata {}

pub type AuthorizationMetadata = ProviderMetadata<
    AdditionalOAuthMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>; // TODO

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::credential_profiles::CoreProfilesMetadata;

    use super::*;

    #[test]
    fn example_credential_metadata_jwt() {
        let _: CredentialMetadata<CoreProfilesMetadata> = serde_json::from_value(json!({
            "format": "jwt_vc_json",
            "id": "UniversityDegree_JWT",
            "cryptographic_binding_methods_supported": [
                "did:example"
            ],
            "cryptographic_suites_supported": [
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
            "proof_types_supported": [
                "jwt"
            ],
            "display": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university"
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                }
            ]
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_metadata_ldp() {
        let _: CredentialMetadata<CoreProfilesMetadata> = serde_json::from_value(json!({
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
            "cryptographic_suites_supported": [
                "Ed25519Signature2018"
            ],
            "credentials_definition": {
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
                        "url": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university"
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                }
            ]
        }))
        .unwrap();
    }

    #[test]
    fn example_credential_metadata_isomdl() {
        let _: CredentialMetadata<CoreProfilesMetadata> = serde_json::from_value(json!({
            "format": "mso_mdoc",
            "doctype": "org.iso.18013.5.1.mDL",
            "cryptographic_binding_methods_supported": [
                "mso"
            ],
            "cryptographic_suites_supported": [
                "ES256", "ES384", "ES512"
            ],
            "display": [
                {
                    "name": "Mobile Driving License",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://examplestate.com/public/mdl.png",
                        "alt_text": "a square figure of a mobile driving license"
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                },
                {
                    "name": "在籍証明書",
                    "locale": "ja-JP",
                    "logo": {
                        "url": "https://examplestate.com/public/mdl.png",
                        "alt_text": "大学のロゴ"
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
