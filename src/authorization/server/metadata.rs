use anyhow::{bail, Result};
use iref::{uri_ref, Uri, UriBuf};
use oauth2::{
    AuthUrl, IntrospectionUrl, PkceCodeChallengeMethod, ResponseType, RevocationUrl, Scope,
    TokenUrl,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

use crate::util::discoverable::Discoverable;

/// Authorization Server Metadata.
///
/// According to [RFC 8414] with the following modifications:
/// * new metadata parameter `pre-authorized_grant_anonymous_access_supported` (as per OID4VP);
/// * `response_types_supported` is now optional (as per OID4VP);
/// * `token_endpoint` is no longer optional (OID4VP cannot be performed without the token
///   endpoint);
/// * additional parameters from
///   [OAuth 2.0 Pushed Authorization Requests](RFC 9126).
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
/// [RFC 8414]: <https://datatracker.ietf.org/doc/html/rfc8414>
/// [RFC 9126]: <https://datatracker.ietf.org/doc/html/rfc9126>
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: UriBuf,
    pub authorization_endpoint: Option<AuthUrl>,
    pub token_endpoint: TokenUrl,
    pub jwks_uri: Option<UriBuf>,
    pub registration_endpoint: Option<UriBuf>,
    pub scopes_supported: Option<Vec<Scope>>,
    pub response_types_supported: Option<Vec<ResponseType>>,
    #[serde(default = "default_response_modes_supported")]
    pub response_modes_supported: Vec<String>,
    #[serde(default = "default_grant_types_supported")]
    pub grant_types_supported: Vec<GrantType>,
    pub revocation_endpoint: Option<RevocationUrl>,
    pub introspection_endpoint: Option<IntrospectionUrl>,
    pub code_challenge_methods_supported: Option<Vec<PkceCodeChallengeMethod>>,
    #[serde(default, rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,
    pub pushed_authorization_request_endpoint: Option<UriBuf>,
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    #[serde(flatten)]
    pub additional_fields: Map<String, Json>,
}

impl AuthorizationServerMetadata {
    pub fn new(issuer: UriBuf, token_endpoint: TokenUrl) -> Self {
        Self {
            issuer,
            authorization_endpoint: Default::default(),
            token_endpoint,
            jwks_uri: Default::default(),
            registration_endpoint: Default::default(),
            scopes_supported: Default::default(),
            response_types_supported: Default::default(),
            response_modes_supported: default_response_modes_supported(),
            grant_types_supported: default_grant_types_supported(),
            revocation_endpoint: Default::default(),
            introspection_endpoint: Default::default(),
            code_challenge_methods_supported: Default::default(),
            pre_authorized_grant_anonymous_access_supported: false,
            pushed_authorization_request_endpoint: Default::default(),
            require_pushed_authorization_requests: Default::default(),
            additional_fields: Default::default(),
        }
    }

    pub fn with_authorization_endpoint(self, authorization_endpoint: AuthUrl) -> Self {
        Self {
            authorization_endpoint: Some(authorization_endpoint),
            ..self
        }
    }

    pub fn additional_fields(&self) -> &Map<String, Json> {
        &self.additional_fields
    }

    pub fn additional_fields_mut(&mut self) -> &mut Map<String, Json> {
        &mut self.additional_fields
    }
}

impl Discoverable for AuthorizationServerMetadata {
    const WELL_KNOWN_URI_REF: &iref::UriRef = uri_ref!(".well-known/oauth-authorization-server");

    fn validate(&self, issuer: &Uri) -> Result<()> {
        if self.issuer != issuer {
            bail!(
                "unexpected issuer URI `{}` (expected `{}`)",
                self.issuer,
                issuer
            )
        }
        Ok(())
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

pub fn default_response_modes_supported() -> Vec<String> {
    vec!["query".to_owned(), "fragment".to_owned()]
}

pub fn default_grant_types_supported() -> Vec<GrantType> {
    vec![GrantType::AuthorizationCode, GrantType::Implicit]
}

#[cfg(feature = "axum")]
mod axum {
    use ::axum::{
        body::Body,
        http::{header::CONTENT_TYPE, StatusCode},
        response::{IntoResponse, Response},
    };

    use crate::util::http::MIME_TYPE_JSON;

    use super::*;

    impl IntoResponse for AuthorizationServerMetadata {
        fn into_response(self) -> Response {
            (&self).into_response()
        }
    }

    impl IntoResponse for &AuthorizationServerMetadata {
        fn into_response(self) -> ::axum::response::Response {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, MIME_TYPE_JSON)
                .body(Body::from(
                    serde_json::to_vec(self)
                        // UNWRAP SAFETY: Authorization Server Metadata is
                        //                always serializable as JSON.
                        .unwrap(),
                ))
                .unwrap()
        }
    }
}
