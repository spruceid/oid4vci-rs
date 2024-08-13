#![allow(clippy::type_complexity)]

use oauth2::{
    http::{header::ACCEPT, HeaderValue, Method, StatusCode},
    AuthUrl, HttpRequest, HttpResponse, TokenUrl,
};
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
        CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType,
        CoreSubjectIdentifierType,
    },
    AdditionalProviderMetadata, DiscoveryError, IssuerUrl, JsonWebKeySetUrl, JsonWebKeyType,
    JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm, LanguageTag, LogoUrl,
    ProviderMetadata, ResponseTypes, Scope,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, KeyValueMap};
use std::{future::Future, marker::PhantomData};

use crate::{
    credential_response_encryption::CredentialResponseEncryptionMetadata,
    http_utils::{check_content_type, MIME_TYPE_JSON},
    profiles::CredentialMetadataProfile,
    proof_of_possession::KeyProofTypesSupported,
    types::ImageUrl,
};

pub use crate::types::{
    BatchCredentialUrl, CredentialUrl, DeferredCredentialUrl, NotificationUrl, ParUrl,
};

const METADATA_URL_SUFFIX: &str = ".well-known/openid-credential-issuer";
const AUTHORIZATION_METADATA_URL_SUFFIX: &str = ".well-known/oauth-authorization-server";

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialIssuerMetadata<CM, JT, JE, JA>
where
    CM: CredentialMetadataProfile,
    JT: JsonWebKeyType,
    JE: JweContentEncryptionAlgorithm<JT>,
    JA: JweKeyManagementAlgorithm + Clone,
{
    credential_issuer: IssuerUrl,
    authorization_servers: Option<Vec<IssuerUrl>>, // Not sure this is the right type
    credential_endpoint: CredentialUrl,
    batch_credential_endpoint: Option<BatchCredentialUrl>,
    deferred_credential_endpoint: Option<DeferredCredentialUrl>,
    notification_endpoint: Option<NotificationUrl>,
    #[serde(
        bound = "JT: JsonWebKeyType, JA: JweKeyManagementAlgorithm, JE: JweContentEncryptionAlgorithm<JT>"
    )]
    credential_response_encryption: Option<CredentialResponseEncryptionMetadata<JT, JE, JA>>,
    credential_identifiers_supported: Option<bool>,
    signed_metadata: Option<String>,
    display: Option<Vec<CredentialIssuerMetadataDisplay>>,
    #[serde(bound = "CM: CredentialMetadataProfile")]
    #[serde_as(as = "KeyValueMap<_>")]
    credential_configurations_supported: Vec<CredentialMetadata<CM>>,
    #[serde(skip)]
    _phantom_jt: PhantomData<JT>,
}

impl<CM, JT, JE, JA> CredentialIssuerMetadata<CM, JT, JE, JA>
where
    CM: CredentialMetadataProfile,
    JT: JsonWebKeyType,
    JE: JweContentEncryptionAlgorithm<JT>,
    JA: JweKeyManagementAlgorithm + Clone,
{
    pub fn new(
        credential_issuer: IssuerUrl,
        credential_endpoint: CredentialUrl,
        credential_configurations_supported: Vec<CredentialMetadata<CM>>,
    ) -> Self {
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
            credential_configurations_supported,
            _phantom_jt: PhantomData,
        }
    }

    field_getters_setters![
        pub self [self] ["issuer metadata value"] {
            set_credential_issuer -> credential_issuer[IssuerUrl],
            set_authorization_servers -> authorization_servers[Option<Vec<IssuerUrl>>],
            set_credential_endpoint -> credential_endpoint[CredentialUrl],
            set_batch_credential_endpoint -> batch_credential_endpoint[Option<BatchCredentialUrl>],
            set_deferred_credential_endpoint -> deferred_credential_endpoint[Option<DeferredCredentialUrl>],
            set_notification_endpoint -> notification_endpoint[Option<NotificationUrl>],
            set_credential_response_encryption -> credential_response_encryption[Option<CredentialResponseEncryptionMetadata<JT, JE, JA>>],
            set_credential_identifiers_supported -> credential_identifiers_supported[Option<bool>],
            set_signed_metadata -> signed_metadata[Option<String>],
            set_display -> display[Option<Vec<CredentialIssuerMetadataDisplay>>],
            set_credential_configurations_supported -> credential_configurations_supported[Vec<CredentialMetadata<CM>>],
        }
    ];

    pub fn discover<HC, RE>(
        issuer_url: &IssuerUrl,
        http_client: HC,
    ) -> Result<Self, DiscoveryError<RE>>
    where
        HC: Fn(HttpRequest) -> Result<HttpResponse, RE>,
        RE: std::error::Error + 'static,
    {
        let discovery_url = issuer_url
            .join(METADATA_URL_SUFFIX)
            .map_err(DiscoveryError::UrlParse)?;

        http_client(Self::discovery_request(discovery_url))
            .map_err(DiscoveryError::Request)
            .and_then(|http_response| Self::discovery_response(issuer_url, http_response))
    }

    pub async fn discover_async<F, HC, RE>(
        issuer_url: IssuerUrl,
        http_client: HC,
    ) -> Result<Self, DiscoveryError<RE>>
    where
        F: Future<Output = Result<HttpResponse, RE>>,
        HC: Fn(HttpRequest) -> F + 'static,
        RE: std::error::Error + 'static,
    {
        let discovery_url = issuer_url
            .join(METADATA_URL_SUFFIX)
            .map_err(DiscoveryError::UrlParse)?;

        http_client(Self::discovery_request(discovery_url))
            .await
            .map_err(DiscoveryError::Request)
            .and_then(|http_response| Self::discovery_response(&issuer_url, http_response))
    }

    fn discovery_request(discovery_url: url::Url) -> HttpRequest {
        HttpRequest {
            url: discovery_url,
            method: Method::GET,
            headers: vec![(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))]
                .into_iter()
                .collect(),
            body: Vec::new(),
        }
    }

    fn discovery_response<RE>(
        issuer_url: &IssuerUrl,
        discovery_response: HttpResponse,
    ) -> Result<Self, DiscoveryError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        if discovery_response.status_code != StatusCode::OK {
            return Err(DiscoveryError::Response(
                discovery_response.status_code,
                discovery_response.body,
                format!("HTTP status code {}", discovery_response.status_code),
            ));
        }

        check_content_type(&discovery_response.headers, MIME_TYPE_JSON).map_err(|err_msg| {
            DiscoveryError::Response(
                discovery_response.status_code,
                discovery_response.body.clone(),
                err_msg,
            )
        })?;

        let provider_metadata = serde_path_to_error::deserialize::<_, Self>(
            &mut serde_json::Deserializer::from_slice(&discovery_response.body),
        )
        .map_err(DiscoveryError::Parse)?;

        if provider_metadata.credential_issuer() != issuer_url {
            Err(DiscoveryError::Validation(format!(
                "unexpected issuer URI `{}` (expected `{}`)",
                provider_metadata.credential_issuer().as_str(),
                issuer_url.as_str()
            )))
        } else {
            Ok(provider_metadata)
        }
    }
}

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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MetadataDisplayLogo {
    url: LogoUrl,
    alt_text: Option<String>,
}

impl MetadataDisplayLogo {
    pub fn new(url: LogoUrl, alt_text: Option<String>) -> Self {
        Self { url, alt_text }
    }

    field_getters_setters![
        pub self [self] ["metadata display logo value"] {
            set_url -> url[LogoUrl],
            set_alt_text -> alt_text[Option<String>],
        }
    ];
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialMetadata<CM>
where
    CM: CredentialMetadataProfile,
{
    #[serde(rename = "$key$")]
    name: Option<String>,
    scope: Option<Scope>,
    cryptographic_binding_methods_supported: Option<Vec<CryptographicBindingMethod>>,
    #[serde_as(as = "Option<KeyValueMap<_>>")]
    proof_types_supported: Option<Vec<KeyProofTypesSupported>>,
    display: Option<Vec<CredentialMetadataDisplay>>,
    #[serde(bound = "CM: CredentialMetadataProfile")]
    #[serde(flatten)]
    additional_fields: CM,
}

// #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
// pub enum CredentialMetadataProfileWrapper<CM>
// where
//     CM: CredentialMetadataProfile,
// {
//     #[serde(flatten, bound = "CM: CredentialMetadataProfile")]
//     Known(CM),
//     #[serde(other)]
//     Unknown,
// }

impl<CM> CredentialMetadata<CM>
where
    CM: CredentialMetadataProfile,
{
    pub fn new(additional_fields: CM) -> Self {
        Self {
            name: None,
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
            set_proof_types_supported -> proof_types_supported[Option<Vec<KeyProofTypesSupported>>],
            set_display -> display[Option<Vec<CredentialMetadataDisplay>>],
            set_additional_fields -> additional_fields[CM],
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
    uri: ImageUrl,
}

impl MetadataBackgroundImage {
    pub fn new(uri: ImageUrl) -> Self {
        Self { uri }
    }

    field_getters_setters![
        pub self [self] ["metadata background image value"] {
            set_uri -> uri[ImageUrl],
        }
    ];
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct AdditionalOAuthMetadata {
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pre_authorized_grant_anonymous_access_supported: Option<bool>,
    pushed_authorization_request_endpoint: Option<ParUrl>,
    require_pushed_authorization_requests: Option<bool>,
}

impl AdditionalOAuthMetadata {
    pub fn set_pushed_authorization_request_endpoint(
        mut self,
        pushed_authorization_request_endpoint: Option<ParUrl>,
    ) -> Self {
        self.pushed_authorization_request_endpoint = pushed_authorization_request_endpoint;
        self
    }

    pub fn set_require_pushed_authorization_requests(
        mut self,
        require_pushed_authorization_requests: Option<bool>,
    ) -> Self {
        self.require_pushed_authorization_requests = require_pushed_authorization_requests;
        self
    }
}

impl AdditionalProviderMetadata for AdditionalOAuthMetadata {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationMetadata(
    ProviderMetadata<
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
    >,
); // TODO, does a oid4vci specific authorization server need a JWKs, and signed JWTs (instead of just JWE), etc?

impl AuthorizationMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: IssuerUrl,
        authorization_endpoint: AuthUrl,
        token_endpoint: TokenUrl,
        jwks_uri: JsonWebKeySetUrl,
        response_types_supported: Vec<ResponseTypes<CoreResponseType>>,
        subject_types_supported: Vec<CoreSubjectIdentifierType>,
        id_token_signing_alg_values_supported: Vec<CoreJwsSigningAlgorithm>,
        additional_metadata: AdditionalOAuthMetadata,
    ) -> Self {
        Self(
            ProviderMetadata::new(
                issuer,
                authorization_endpoint,
                jwks_uri,
                response_types_supported,
                subject_types_supported,
                id_token_signing_alg_values_supported,
                additional_metadata,
            )
            .set_token_endpoint(Some(token_endpoint)),
        )
    }

    pub fn discover<LF, HC, RE, CM, JT, JE, JA>(
        credential_issuer_metadata: &CredentialIssuerMetadata<CM, JT, JE, JA>,
        grant_type: Option<CoreGrantType>,
        http_client: HC,
        logging_fn: Option<LF>,
    ) -> Result<Self, DiscoveryError<RE>>
    where
        LF: Fn(&DiscoveryError<RE>),
        HC: Fn(HttpRequest) -> Result<HttpResponse, RE>,
        RE: std::error::Error + 'static,
        CM: CredentialMetadataProfile,
        JT: JsonWebKeyType,
        JE: JweContentEncryptionAlgorithm<JT>,
        JA: JweKeyManagementAlgorithm + Clone,
    {
        let log_and_continue = |e: DiscoveryError<RE>| -> DiscoveryError<RE> {
            if let Some(ref logging_fn) = logging_fn {
                logging_fn(&e);
            }
            e
        };

        let discover_url = |url: &IssuerUrl| -> Result<Self, DiscoveryError<RE>> {
            let issuer_url = url.clone();

            let discovery_url = issuer_url
                .join(AUTHORIZATION_METADATA_URL_SUFFIX)
                .map_err(DiscoveryError::UrlParse)
                .map_err(log_and_continue)?;

            http_client(Self::discovery_request(discovery_url))
                .map_err(DiscoveryError::Request)
                .map_err(log_and_continue)
                .and_then(|http_response| Self::discovery_response(&issuer_url, http_response))
                .map_err(log_and_continue)
        };

        let default = || discover_url(&credential_issuer_metadata.credential_issuer);

        match (
            &credential_issuer_metadata.authorization_servers,
            grant_type,
        ) {
            (Some(servers), Some(grant_type)) => {
                if servers.is_empty() {
                    // The `authorization_servers` field is an empty array, it could be
                    // treated as an error, but we default to try `credential_issuer`.
                    //
                    // ```
                    // DiscoveryError::Other(
                    //     "failed to select an authorization server: no matching grant_type".to_string(),
                    // )
                    // ```
                    return default();
                }

                let server = servers
                    .iter()
                    .map(|auth_server| {
                        let response = discover_url(auth_server)?;

                        Ok::<Option<Self>, DiscoveryError<RE>>(
                            response.0.grant_types_supported().and_then(|gts| {
                                if gts.iter().any(|gt| *gt == grant_type) {
                                    Some(response.clone())
                                } else {
                                    None
                                }
                            }),
                        )
                    })
                    .take_while(|s| !matches!(s, Ok(Some(_))))
                    .next();

                match server {
                    Some(Ok(Some(s))) => Ok(s),
                    Some(Ok(None)) => {
                        // Could return an error because no servers have successfully matched the
                        // specified `grant_type`.
                        //
                        // ```
                        // DiscoveryError::Other(
                        //     "failed to select an authorization server: no matching grant_type".to_string(),
                        // )
                        // ```
                        default()
                    }
                    Some(Err(_)) => {
                        // This will contain the errors of the last `authorization_servers`'s entry
                        // discovery calls, could also be handled differently.
                        //
                        // ```
                        // DiscoveryError::Other(
                        //     "failed to select an authorization server: no matching grant_type".to_string(),
                        // )
                        // ```
                        default()
                    }
                    None => {
                        // Could return an error because no servers have successfully matched the
                        // specified `grant_type`.
                        //
                        // ```
                        // DiscoveryError::Other(
                        //     "failed to select an authorization server: no matching grant_type".to_string(),
                        // )
                        // ```
                        default()
                    }
                }
            }
            _ => default(),
        }
    }

    pub async fn discover_async<F, LF, HC, RE, CM, JT, JE, JA>(
        credential_issuer_metadata: &CredentialIssuerMetadata<CM, JT, JE, JA>,
        grant_type: Option<CoreGrantType>,
        http_client: HC,
        logging_fn: Option<LF>,
    ) -> Result<Self, DiscoveryError<RE>>
    where
        F: Future<Output = Result<HttpResponse, RE>>,
        LF: Fn(&DiscoveryError<RE>),
        HC: Fn(HttpRequest) -> F + 'static,
        RE: std::error::Error + 'static,
        CM: CredentialMetadataProfile,
        JT: JsonWebKeyType,
        JE: JweContentEncryptionAlgorithm<JT>,
        JA: JweKeyManagementAlgorithm + Clone,
    {
        type S = AuthorizationMetadata;

        async fn discover_inner<F, LF, HC, RE>(
            url: &IssuerUrl,
            http_client: &HC,
            logging_fn: Option<&LF>,
        ) -> Result<S, DiscoveryError<RE>>
        where
            F: Future<Output = Result<HttpResponse, RE>>,
            LF: Fn(&DiscoveryError<RE>),
            HC: Fn(HttpRequest) -> F + 'static,
            RE: std::error::Error + 'static,
        {
            let log_and_continue = |e: DiscoveryError<RE>| -> DiscoveryError<RE> {
                if let Some(ref logging_fn) = logging_fn {
                    logging_fn(&e);
                }
                e
            };

            let issuer_url = url.clone();

            let discovery_url = issuer_url
                .join(AUTHORIZATION_METADATA_URL_SUFFIX)
                .map_err(DiscoveryError::UrlParse)
                .map_err(log_and_continue)?;

            http_client(S::discovery_request(discovery_url))
                .await
                .map_err(DiscoveryError::Request)
                .map_err(log_and_continue)
                .and_then(|http_response| S::discovery_response(&issuer_url, http_response))
                .map_err(log_and_continue)
        }

        match (
            &credential_issuer_metadata.authorization_servers,
            grant_type,
        ) {
            (Some(servers), Some(grant_type)) => {
                if servers.is_empty() {
                    // The `authorization_servers` field is an empty array, it could be
                    // treated as an error, but we default to try `credential_issuer`.
                    //
                    // ```
                    // DiscoveryError::Other(
                    //     "failed to select an authorization server: no matching grant_type".to_string(),
                    // )
                    // ```
                    return discover_inner(
                        &credential_issuer_metadata.credential_issuer,
                        &http_client,
                        logging_fn.as_ref(),
                    )
                    .await;
                }

                for auth_server in servers {
                    let response =
                        discover_inner(auth_server, &http_client, logging_fn.as_ref()).await;

                    match response {
                        Ok(response) if response.0.grant_types_supported().is_some() => {
                            if response
                                .0
                                .grant_types_supported()
                                .unwrap()
                                .iter()
                                .any(|gt| *gt == grant_type)
                            {
                                return Ok(response.clone());
                            }
                        }
                        _ => continue,
                    }
                }

                // Could return an error because no servers have successfully matched the
                // specified `grant_type`.
                //
                // ```
                // DiscoveryError::Other(
                //     "failed to select an authorization server: no matching grant_type".to_string(),
                // )
                // ```
                discover_inner(
                    &credential_issuer_metadata.credential_issuer,
                    &http_client,
                    logging_fn.as_ref(),
                )
                .await
            }
            _ => {
                discover_inner(
                    &credential_issuer_metadata.credential_issuer,
                    &http_client,
                    logging_fn.as_ref(),
                )
                .await
            }
        }
    }

    fn discovery_request(discovery_url: url::Url) -> HttpRequest {
        HttpRequest {
            url: discovery_url,
            method: Method::GET,
            headers: vec![(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))]
                .into_iter()
                .collect(),
            body: Vec::new(),
        }
    }

    fn discovery_response<RE>(
        issuer_url: &IssuerUrl,
        discovery_response: HttpResponse,
    ) -> Result<Self, DiscoveryError<RE>>
    where
        RE: std::error::Error + 'static,
    {
        if discovery_response.status_code != StatusCode::OK {
            return Err(DiscoveryError::Response(
                discovery_response.status_code,
                discovery_response.body,
                format!("HTTP status code {}", discovery_response.status_code),
            ));
        }

        check_content_type(&discovery_response.headers, MIME_TYPE_JSON).map_err(|err_msg| {
            DiscoveryError::Response(
                discovery_response.status_code,
                discovery_response.body.clone(),
                err_msg,
            )
        })?;

        let provider_metadata = serde_path_to_error::deserialize::<_, Self>(
            &mut serde_json::Deserializer::from_slice(&discovery_response.body),
        )
        .map_err(DiscoveryError::Parse)?;

        if provider_metadata.0.issuer() != issuer_url {
            Err(DiscoveryError::Validation(format!(
                "unexpected issuer URI `{}` (expected `{}`)",
                provider_metadata.0.issuer().as_str(),
                issuer_url.as_str()
            )))
        } else {
            Ok(provider_metadata)
        }
    }

    pub fn authorization_endpoint(&self) -> &AuthUrl {
        self.0.authorization_endpoint()
    }

    pub fn pushed_authorization_endpoint(&self) -> Option<ParUrl> {
        self.0
            .additional_metadata()
            .clone()
            .pushed_authorization_request_endpoint
    }

    pub fn token_endpoint(&self) -> &TokenUrl {
        // TODO find better way to avoid unwrap
        self.0.token_endpoint().unwrap()
    }
}

#[cfg(test)]
mod test {
    use crate::core::profiles::CoreProfilesMetadata;
    use serde_json::json;

    use super::*;

    #[test]
    fn example_credential_issuer_metadata() {
        let _: CredentialIssuerMetadata<
            CoreProfilesMetadata,
            CoreJsonWebKeyType,
            CoreJweContentEncryptionAlgorithm,
            CoreJweKeyManagementAlgorithm,
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
                                "url": "https://university.example.edu/public/logo.png",
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
        let _: CredentialMetadata<CoreProfilesMetadata> = serde_json::from_value(json!({
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
                        "url": "https://exampleuniversity.com/public/logo.png",
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
            "credential_signing_alg_values_supported": [
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
        let _: CredentialMetadata<CoreProfilesMetadata> = serde_json::from_value(json!({
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
                        "url": "https://examplestate.com/public/mdl.png",
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
                        "url": "https://examplestate.com/public/mdl.png",
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
