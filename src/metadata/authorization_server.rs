use anyhow::{bail, Result};
use oauth2::{
    AsyncHttpClient, AuthUrl, IntrospectionUrl, PkceCodeChallengeMethod, ResponseType,
    RevocationUrl, Scope, SyncHttpClient, TokenUrl,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};
use tracing::{info, warn};

use crate::{
    profiles::CredentialConfigurationProfile,
    types::{IssuerUrl, JsonWebKeySetUrl, ParUrl, RegistrationUrl, ResponseMode},
};

use super::{CredentialIssuerMetadata, MetadataDiscovery};

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
    #[serde(flatten)]
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

    /// Discover the authorization server metadata, potentially from a list of authorization
    /// servers in the credential issuer metadata.
    ///
    /// Optionally the grant type and authorization server (i.e. from the credential offer) can be
    /// provided to help select the correct authorization server.
    pub fn discover_from_credential_issuer_metadata<C, CM>(
        http_client: &C,
        credential_issuer_metadata: &CredentialIssuerMetadata<CM>,
        grant_type: Option<&GrantType>,
        authorization_server: Option<&IssuerUrl>,
    ) -> Result<Self, anyhow::Error>
    where
        C: SyncHttpClient,
        C::Error: Send + Sync,
        CM: CredentialConfigurationProfile,
    {
        let credential_issuer_authorization_server_metadata =
            Self::discover(credential_issuer_metadata.credential_issuer(), http_client);
        let Some(grant_type) = grant_type else {
            // If grants is not present or is empty, the Wallet MUST determine the Grant Types the
            // Credential Issuer's Authorization Server supports using the respective metadata.
            // When multiple grants are present, it is at the Wallet's discretion which one to use.
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-4.1.1-2.3
            return credential_issuer_authorization_server_metadata;
        };

        if let Some(servers) = credential_issuer_metadata.authorization_servers() {
            // the Wallet can use to identify the Authorization Server to use with this grant type
            // when authorization_servers parameter in the Credential Issuer metadata has multiple
            // entries. It MUST NOT be used otherwise.
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-4.1.1-4.1.2.2
            if let Some(server) = authorization_server {
                if servers.len() > 1 && servers.contains(server) {
                    return Self::discover(server, http_client);
                }
            }
            for auth_server in servers {
                let response = Self::discover(auth_server, http_client);
                match response {
                    Ok(response) => {
                        if response
                            .grant_types_supported()
                            .0
                            .iter()
                            .any(|gt| gt == grant_type)
                        {
                            return Ok(response);
                        } else {
                            info!("Auth server not supporting grant type, trying the next one");
                        }
                    }
                    Err(e) => {
                        warn!("Error fetching auth server metadata, trying the next one: {e:?}");
                    }
                }
            }
        }

        // Fallback to credential issuer authorization server.
        credential_issuer_authorization_server_metadata
    }

    /// Discover the authorization server metadata, potentially from a list of authorization
    /// servers in the credential issuer metadata.
    ///
    /// Optionally the grant type and authorization server (i.e. from the credential offer) can be
    /// provided to help select the correct authorization server.
    pub async fn discover_from_credential_issuer_metadata_async<'c, C, CM>(
        http_client: &'c C,
        credential_issuer_metadata: &CredentialIssuerMetadata<CM>,
        grant_type: Option<&GrantType>,
        authorization_server: Option<&IssuerUrl>,
    ) -> Result<Self, anyhow::Error>
    where
        C: AsyncHttpClient<'c>,
        C::Error: Send + Sync,
        CM: CredentialConfigurationProfile,
    {
        let credential_issuer_authorization_server_metadata =
            Self::discover_async(credential_issuer_metadata.credential_issuer(), http_client).await;
        let Some(grant_type) = grant_type else {
            // If grants is not present or is empty, the Wallet MUST determine the Grant Types the
            // Credential Issuer's Authorization Server supports using the respective metadata.
            // When multiple grants are present, it is at the Wallet's discretion which one to use.
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-4.1.1-2.3
            return credential_issuer_authorization_server_metadata;
        };

        if let Some(servers) = credential_issuer_metadata.authorization_servers() {
            // the Wallet can use to identify the Authorization Server to use with this grant type
            // when authorization_servers parameter in the Credential Issuer metadata has multiple
            // entries. It MUST NOT be used otherwise.
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-4.1.1-4.1.2.2
            if let Some(server) = authorization_server {
                if servers.len() > 1 && servers.contains(server) {
                    return Self::discover_async(server, http_client).await;
                }
            }
            for auth_server in servers {
                let response = Self::discover_async(auth_server, http_client).await;
                match response {
                    Ok(response) => {
                        if response
                            .grant_types_supported()
                            .0
                            .iter()
                            .any(|gt| gt == grant_type)
                        {
                            return Ok(response);
                        } else {
                            info!("Auth server not supporting grant type, trying the next one");
                        }
                    }
                    Err(e) => {
                        warn!("Error fetching auth server metadata, trying the next one: {e:?}");
                    }
                }
            }
        }

        // Fallback to credential issuer authorization server.
        credential_issuer_authorization_server_metadata
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
