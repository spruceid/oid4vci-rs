use anyhow::{bail, Result};
use oauth2::{
    AuthUrl, IntrospectionUrl, PkceCodeChallengeMethod, ResponseType, RevocationUrl, Scope,
    TokenUrl,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

use crate::types::{IssuerUrl, JsonWebKeySetUrl, ParUrl, RegistrationUrl, ResponseMode};

use super::MetadataDiscovery;

/// Authorization Server Metadata according to
/// [RFC8414](https://datatracker.ietf.org/doc/html/rfc8414) with the following modifications:
/// * new metadata parameter `pre-authorized_grant_anonymous_access_supported` (as per OID4VP);
/// * `response_types_supported` is now optional (as per OID4VP);
/// * `token_endpoint` is no longer optional (OID4VP cannot be performed without the token
///   endpoint);
/// * additional parameters from
///   [OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126).
/// * the following parameters from RFC 8414 are not yet implemented, but may still be accessed via
///   `additional_fields`:
///   * `token_endpoint_auth_methods_supported`
///   * `token_endpoint_auth_signing_alg_values_supported`
///   * `service_documentation`
///   * `ui_locales_supported`
///   * `op_policy_uri`
///   * `op_tos_uri`
///   * `revocation_endpoint_auth_methods_supported`
///   * `revocation_endpoint_auth_singing_alg_values_supported`
///   * `introspection_endpoint_auth_methods_supported`
///   * `introspection_endpoint_auth_singing_alg_values_supported`
///   
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationServerMetadata {
    issuer: IssuerUrl,
    authorization_endpoint: Option<AuthUrl>,
    token_endpoint: TokenUrl,
    jwks_uri: Option<JsonWebKeySetUrl>,
    registration_endpoint: Option<RegistrationUrl>,
    scopes_supported: Option<Vec<Scope>>,
    response_types_supported: Option<Vec<ResponseType>>,
    #[serde(default)]
    response_modes_supported: ResponseModes,
    #[serde(default)]
    grant_types_supported: GrantTypesSupported,
    revocation_endpoint: Option<RevocationUrl>,
    introspection_endpoint: Option<IntrospectionUrl>,
    code_challenge_methods_supported: Option<Vec<PkceCodeChallengeMethod>>,
    #[serde(default, rename = "pre-authorized_grant_anonymous_access_supported")]
    pre_authorized_grant_anonymous_access_supported: bool,
    pushed_authorization_request_endpoint: Option<ParUrl>,
    #[serde(default)]
    require_pushed_authorization_requests: bool,
    additional_fields: Map<String, Json>,
}

impl AuthorizationServerMetadata {
    #[cfg(test)]
    pub fn new(issuer: IssuerUrl, token_endpoint: TokenUrl) -> Self {
        Self {
            issuer,
            authorization_endpoint: Default::default(),
            token_endpoint,
            jwks_uri: Default::default(),
            registration_endpoint: Default::default(),
            scopes_supported: Default::default(),
            response_types_supported: Default::default(),
            response_modes_supported: Default::default(),
            grant_types_supported: Default::default(),
            revocation_endpoint: Default::default(),
            introspection_endpoint: Default::default(),
            code_challenge_methods_supported: Default::default(),
            pre_authorized_grant_anonymous_access_supported: false,
            pushed_authorization_request_endpoint: Default::default(),
            require_pushed_authorization_requests: Default::default(),
            additional_fields: Default::default(),
        }
    }

    field_getters_setters![
        pub self [self] ["authorization server metadata value"] {
            set_issuer -> issuer[IssuerUrl],
            set_authorization_endpoint -> authorization_endpoint[Option<AuthUrl>],
            set_token_endpoint -> token_endpoint[TokenUrl],
            set_jwks_uri -> jwks_uri[Option<JsonWebKeySetUrl>],
            set_registration_endpoint -> registration_endpoint[Option<RegistrationUrl>],
            set_scopes_supported -> scopes_supported[Option<Vec<Scope>>],
            set_response_types_supported -> response_types_supported[Option<Vec<ResponseType>>],
            set_response_modes_supported -> response_modes_supported[ResponseModes],
            set_grant_types_supported -> grant_types_supported[GrantTypesSupported],
            set_revocation_endpoint -> revocation_endpoint[Option<RevocationUrl>],
            set_introspection_endpoint -> introspection_endpoint[Option<IntrospectionUrl>],
            set_code_challenge_methods_supported -> code_challenge_methods_supported[Option<Vec<PkceCodeChallengeMethod>>],
            set_pre_authorized_grant_anonymous_access_supported -> pre_authorized_grant_anonymous_access_supported[bool],
            set_pushed_authorization_request_endpoint -> pushed_authorization_request_endpoint[Option<ParUrl>],
            set_require_pushed_authorization_requests -> require_pushed_authorization_requests[bool],
        }
    ];

    pub fn additional_fields(&self) -> &Map<String, Json> {
        &self.additional_fields
    }

    pub fn additional_fields_mut(&mut self) -> &mut Map<String, Json> {
        &mut self.additional_fields
    }
}

impl MetadataDiscovery for AuthorizationServerMetadata {
    const METADATA_URL_SUFFIX: &'static str = ".well-known/oauth-authorization-server";

    fn validate(&self, issuer: &IssuerUrl) -> Result<()> {
        if self.issuer() != issuer {
            bail!(
                "unexpected issuer URI `{}` (expected `{}`)",
                self.issuer().as_str(),
                issuer.as_str()
            )
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseModes(pub Vec<ResponseMode>);

impl Default for ResponseModes {
    fn default() -> Self {
        Self(vec![
            ResponseMode::new("query".to_owned()),
            ResponseMode::new("fragment".to_owned()),
        ])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrantTypesSupported(pub Vec<GrantType>);

impl Default for GrantTypesSupported {
    fn default() -> Self {
        Self(vec![GrantType::AuthorizationCode, GrantType::Implicit])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    Implicit,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode,
    #[serde(untagged)]
    Extension(String),
}
