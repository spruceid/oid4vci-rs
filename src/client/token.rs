use iref::Uri;
use open_auth2::{endpoints::token::TokenResponse, AccessToken, Scope, ScopeBuf};
use serde::{Deserialize, Serialize};

use crate::{
    authorization::{
        authorization_details::CredentialAuthorizationDetailsResponse,
        server::Oid4vciAuthorizationServerMetadata,
    },
    client::{ClientError, ResolvedCredentialOffer},
    credential::{CredentialOrConfigurationId, CredentialOrConfigurationIdRef},
    issuer::metadata::{CredentialConfiguration, CredentialFormatMetadata},
    profile::ProfileCredentialAuthorizationDetailsResponse,
    Profile, StandardProfile,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "P: Profile")]
pub struct Oid4vciTokenParams<P: Profile = StandardProfile> {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_details: Vec<CredentialAuthorizationDetailsResponse<P::AuthorizationParams>>,
}

/// Credential Token.
///
/// Stores the necessary information to query a credential through the
/// [`Oid4vciClient::exchange_credential`] method.
///
/// You can use the [`Oid4vciClient::get_nonce`] method to query a nonce value from the
/// server, to use with proof of possessions.
///
/// [`Oid4vciClient::exchange_credential`]: crate::Oid4vciClient::exchange_credential
/// [`Oid4vciClient::get_nonce`]: crate::Oid4vciClient::get_nonce
pub struct CredentialToken<P: Profile = StandardProfile> {
    pub(crate) credential_offer: ResolvedCredentialOffer<P>,
    pub(crate) authorization_server_metadata: Oid4vciAuthorizationServerMetadata,
    pub(crate) requested_scope: Option<ScopeBuf>,
    pub(crate) response: TokenResponse<String, Oid4vciTokenParams<P>>,
}

impl<P: Profile> CredentialToken<P> {
    pub fn get(&self) -> &AccessToken {
        &self.response.access_token
    }

    pub fn credential_issuer(&self) -> &Uri {
        &self.credential_offer.params.credential_issuer
    }

    pub fn credential_offer(&self) -> &ResolvedCredentialOffer<P> {
        &self.credential_offer
    }

    pub fn authorization_server_metadata(&self) -> &Oid4vciAuthorizationServerMetadata {
        &self.authorization_server_metadata
    }

    pub fn scope(&self) -> Option<&Scope> {
        self.response
            .scope
            .as_deref()
            .or(self.requested_scope.as_deref())
    }

    pub fn authorization_details(&self) -> &[ProfileCredentialAuthorizationDetailsResponse<P>] {
        &self.response.ext.authorization_details
    }

    /// Returns the configuration behind the given credential or configuration
    /// id.
    pub fn credential_configuration_id<'a>(
        &'a self,
        credential: impl Into<CredentialOrConfigurationIdRef<'a>>,
    ) -> Option<&'a str> {
        match credential.into() {
            CredentialOrConfigurationIdRef::Credential(id) => self
                .response
                .ext
                .authorization_details
                .iter()
                .find_map(|details| {
                    details
                        .credential_identifiers
                        .iter()
                        .any(|cid| cid == id)
                        .then_some(details.credential_configuration_id.as_str())
                }),
            CredentialOrConfigurationIdRef::Configuration(id) => Some(id),
        }
    }

    /// Returns the configuration behind the given credential or configuration
    /// id.
    pub fn credential_configuration<'a>(
        &'a self,
        credential: impl Into<CredentialOrConfigurationIdRef<'a>>,
    ) -> Option<(&'a str, &'a CredentialConfiguration<P::FormatMetadata>)> {
        self.credential_configuration_id(credential).and_then(|id| {
            self.credential_offer
                .issuer_metadata
                .credential_configurations_supported
                .get(id)
                .map(|conf| (id, conf))
        })
    }

    /// Returns the credential format of the given credential or configuration.
    pub fn credential_format<'a>(
        &'a self,
        credential: impl Into<CredentialOrConfigurationIdRef<'a>>,
    ) -> Option<P::Format> {
        self.credential_configuration(credential)
            .map(|(_, conf)| conf.format.id())
    }

    pub fn default_credential_id(&self) -> Result<CredentialOrConfigurationId, ClientError> {
        match self.authorization_details() {
            [] => match self
                .credential_offer
                .params
                .credential_configuration_ids
                .as_slice()
            {
                [id] => Ok(CredentialOrConfigurationId::Configuration(id.clone())),
                _ => Err(ClientError::AmbiguousCredentialOffer),
            },
            [details] => match details.credential_identifiers.as_slice() {
                [id] => Ok(CredentialOrConfigurationId::Credential(id.clone())),
                _ => Err(ClientError::AmbiguousCredentialOffer),
            },
            _ => Err(ClientError::AmbiguousCredentialOffer),
        }
    }
}
