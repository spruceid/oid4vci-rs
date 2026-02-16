use std::{borrow::Cow, marker::PhantomData};

use iref::{Uri, UriBuf};
use open_auth2::{
    client::OAuth2Client,
    endpoints::token::{TokenEndpoint, TokenResponse},
    ext::rar::AddAuthorizationDetails,
    transport::HttpClient,
    util::Discoverable,
    AddAccessToken, ClientId, ClientIdBuf, ScopeBuf,
};
use ssi::{
    claims::{jws::JwsSigner, Jws, JwsBuf},
    JWK,
};

use crate::{
    authorization::{
        authorization_details::{
            CredentialAuthorizationDetailsRequest, CredentialAuthorizationParams,
        },
        oauth2::{
            client_attestation::{AddClientAttestation, AttestedOAuth2Client},
            dpop::{AddDpop, OAuth2DpopClient},
        },
        server::Oid4vciAuthorizationServerMetadata,
    },
    credential::CredentialOrConfigurationId,
    endpoints::{CredentialEndpoint, NonceEndpoint},
    issuer::{metadata::CredentialFormatMetadata, CredentialIssuerMetadata},
    offer::{AuthorizationCodeGrant, CredentialOfferParameters, PreAuthorizedCodeGrant},
    profile::{ProfileCredentialAuthorizationDetailsRequest, ProfileCredentialResponse},
    proof::Proofs,
    util::no_signer::NoSigner,
    CredentialOffer, Profile, StandardProfile,
};

mod error;
mod flow;
mod offer;
mod token;

pub use error::*;
pub use flow::*;
pub use offer::*;
pub use token::*;

/// OID4VCI client.
///
/// Unless you need custom ways of configuring authorization and token requests,
/// you probably want to use the [`SimpleOid4vciClient`] implementation
/// directly.
pub trait Oid4vciClient:
    Clone
    + OAuth2Client<TokenResponse = TokenResponse<String, Oid4vciTokenParams<Self::Profile>>>
    + AttestedOAuth2Client
    + OAuth2DpopClient
{
    /// OID4VCI profile.
    type Profile: Profile;

    /// Configures the credentials requested for issuance in an Authorization
    /// Request.
    ///
    /// Implementors do not need to set the `locations` value of the
    /// authorization details manually.
    fn configure_authorization_request(
        &self,
        offer: &ResolvedCredentialOffer<Self::Profile>,
        _authorization_server_metadata: &Oid4vciAuthorizationServerMetadata,
    ) -> Result<CredentialRequestConfiguration<Self::Profile>, ClientError> {
        let mut result = CredentialRequestConfiguration::default();

        for id in &offer.params.credential_configuration_ids {
            if let Some(conf) = offer
                .issuer_metadata
                .credential_configurations_supported
                .get(id)
            {
                if let Some(scope) = &conf.scope {
                    match &mut result.scope {
                        Some(s) => s.extend(scope),
                        None => result.scope = Some(scope.clone()),
                    }
                }
            }
        }

        Ok(result)
    }

    /// Configures the credential requested for issuance in a Token Request.
    ///
    /// Implementors do not need to set the `locations` value of the
    /// authorization details manually.
    fn configure_token_request(
        &self,
        _offer: &ResolvedCredentialOffer<Self::Profile>,
    ) -> Result<Vec<ProfileCredentialAuthorizationDetailsRequest<Self::Profile>>, ClientError> {
        Ok(Vec::new())
    }

    /// Selects the preferred grant.
    ///
    /// The default implementation favors the `pre_authorized_code` grant.
    fn select_grant<'a>(
        &self,
        credential_offer: &'a CredentialOfferParameters,
    ) -> Result<GrantSelection<'a>, ClientError> {
        credential_offer
            .grants
            .pre_authorized_code
            .as_ref()
            .map(Cow::Borrowed)
            .map(GrantSelection::PreAuthorizedCode)
            .or_else(|| {
                credential_offer
                    .grants
                    .authorization_code
                    .as_ref()
                    .map(Cow::Borrowed)
                    .map(GrantSelection::AuthorizationCode)
            })
            .ok_or(ClientError::MissingGrant)
    }

    /// Resolves a credential offer, fetching its parameter and issuer metadata.
    #[allow(async_fn_in_trait)]
    async fn resolve_offer(
        &self,
        http_client: &impl HttpClient,
        credential_offer: CredentialOffer,
    ) -> Result<ResolvedCredentialOffer<Self::Profile>, ClientError> {
        let params = credential_offer.resolve(http_client).await?;

        let issuer_metadata =
            CredentialIssuerMetadata::<<Self::Profile as Profile>::FormatMetadata>::discover(
                http_client,
                &params.credential_issuer,
            )
            .await?;

        Ok(ResolvedCredentialOffer {
            params,
            issuer_metadata,
        })
    }

    /// Process a credential offer.
    #[allow(async_fn_in_trait)]
    async fn accept_offer(
        &self,
        http_client: &impl HttpClient,
        credential_offer: ResolvedCredentialOffer<Self::Profile>,
    ) -> Result<CredentialTokenState<Self>, ClientError> {
        log::debug!("selecting grant");
        match self.select_grant(&credential_offer.params)? {
            GrantSelection::AuthorizationCode(grant) => {
                log::debug!("authorization code grant");
                let authorization_server_url = select_authorization_server(
                    grant.authorization_server.as_deref(),
                    &credential_offer.params.credential_issuer,
                    &credential_offer.issuer_metadata.authorization_servers,
                )?;

                let authorization_server_metadata = Oid4vciAuthorizationServerMetadata::discover(
                    http_client,
                    authorization_server_url,
                )
                .await?;

                let issuer_state = grant.issuer_state.clone();

                Ok(CredentialTokenState::RequiresAuthorizationCode(
                    AuthorizationCodeRequired::new(
                        self.clone(),
                        credential_offer,
                        issuer_state,
                        authorization_server_metadata,
                    ),
                ))
            }
            GrantSelection::PreAuthorizedCode(grant) => {
                log::debug!("pre-authorized code grant");
                let authorization_server_url = select_authorization_server(
                    grant.authorization_server.as_deref(),
                    &credential_offer.params.credential_issuer,
                    &credential_offer.issuer_metadata.authorization_servers,
                )?;

                let authorization_server_metadata = Oid4vciAuthorizationServerMetadata::discover(
                    http_client,
                    authorization_server_url,
                )
                .await?;

                match grant.tx_code.clone() {
                    Some(tx_code_definition) => {
                        log::debug!("transaction code required");
                        let pre_authorized_code = grant.pre_authorized_code.clone();

                        Ok(CredentialTokenState::RequiresTxCode(TxCodeRequired::new(
                            self.clone(),
                            credential_offer,
                            authorization_server_metadata,
                            pre_authorized_code,
                            tx_code_definition,
                        )))
                    }
                    None => {
                        log::debug!("no transaction code required");
                        let mut authorization_details =
                            self.configure_token_request(&credential_offer)?;

                        set_locations(
                            &credential_offer.issuer_metadata,
                            &mut authorization_details,
                        );

                        let token_endpoint = TokenEndpoint::new(
                            self,
                            authorization_server_metadata
                                .token_endpoint
                                .as_deref()
                                .ok_or(ClientError::MissingTokenEndpoint)?,
                        );

                        let response = token_endpoint
                            .exchange_pre_authorized_code(grant.pre_authorized_code.clone(), None)
                            .with_authorization_details(&authorization_details)
                            .with_client_attestation(&authorization_server_metadata)
                            .with_dpop(None, None)
                            .send(http_client)
                            .await
                            .map_err(|_| ClientError::Authorization)?;

                        Ok(CredentialTokenState::Ready(CredentialToken {
                            credential_offer,
                            authorization_server_metadata,
                            requested_scope: None,
                            response,
                        }))
                    }
                }
            }
        }
    }

    #[allow(async_fn_in_trait)]
    async fn get_nonce(
        &self,
        token: &CredentialToken<Self::Profile>,
        http_client: &impl HttpClient,
    ) -> Result<Option<String>, ClientError> {
        match &token.credential_offer.issuer_metadata.nonce_endpoint {
            Some(nonce_endpoint_uri) => {
                let nonce_endpoint = NonceEndpoint::new(self, nonce_endpoint_uri);
                let response = nonce_endpoint.get().send(http_client).await?;
                Ok(Some(response.c_nonce))
            }
            None => Ok(None),
        }
    }

    #[allow(async_fn_in_trait)]
    async fn exchange_credential(
        &self,
        http_client: &impl HttpClient,
        token: &CredentialToken<Self::Profile>,
        credential: CredentialOrConfigurationId,
        proofs: Option<Proofs>,
    ) -> Result<ProfileCredentialResponse<Self::Profile>, ClientError>
    where
        <Self::Profile as Profile>::RequestParams: Default,
    {
        self.exchange_credential_with(http_client, token, credential, proofs, Default::default())
            .await
    }

    #[allow(async_fn_in_trait)]
    async fn exchange_credential_with(
        &self,
        http_client: &impl HttpClient,
        token: &CredentialToken<Self::Profile>,
        credential: CredentialOrConfigurationId,
        proofs: Option<Proofs>,
        params: <Self::Profile as Profile>::RequestParams,
    ) -> Result<ProfileCredentialResponse<Self::Profile>, ClientError> {
        let credential_endpoint = CredentialEndpoint::new(
            self,
            &token.credential_offer.issuer_metadata.credential_endpoint,
        );

        let credential = credential_endpoint
            .exchange_credential(
                credential, proofs, None, // TODO support encryption
                params,
            )
            .with_access_token(&token.response.token_type, &token.response.access_token)
            .with_dpop(Some(&token.response.access_token), None)
            .send(http_client)
            .await?;

        // TODO: I'm disabling notification for now, util we know how/where/when
        //       we want to send them.
        // if let CredentialResponse::Immediate(ImmediateCredentialResponse {
        //     notification_id: Some(notification_id),
        //     ..
        // }) = &credential
        // {
        //     if let Some(notification_endpoint_url) =
        //         &token.credential_offer.issuer_metadata.notification_endpoint
        //     {
        //         let notification_endpoint =
        //             NotificationEndpoint::new(self, notification_endpoint_url);

        //         log::info!("notifying issuer");

        //         let result = notification_endpoint
        //             .notify(
        //                 notification_id.clone(),
        //                 NotificationEventType::CredentialAccepted,
        //                 None,
        //             )
        //             .with_access_token(&token.response.token_type, &token.response.access_token)
        //             .with_dpop(Some(&token.response.access_token), None)
        //             .send(http_client)
        //             .await;

        //         if let Err(e) = result {
        //             log::warn!("unable to notify issuer: {e}")
        //         }
        //     } else {
        //         log::warn!("there is a notification id but no notification endpoint")
        //     }
        // } else {
        //     log::warn!("no notification id")
        // }

        Ok(credential)
    }
}

fn set_locations<F, C>(
    issuer_metadata: &CredentialIssuerMetadata<F>,
    authorization_details: &mut [CredentialAuthorizationDetailsRequest<C>],
) where
    F: CredentialFormatMetadata,
    C: CredentialAuthorizationParams,
{
    if !issuer_metadata.authorization_servers.is_empty() {
        for d in authorization_details {
            if !d.locations.contains(&issuer_metadata.credential_issuer) {
                d.locations.push(issuer_metadata.credential_issuer.clone());
            }
        }
    }
}

/// Selected grant.
pub enum GrantSelection<'a> {
    /// Authorization Code Flow.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow>
    AuthorizationCode(Cow<'a, AuthorizationCodeGrant>),

    /// Pre-Authorized Code Flow.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow>
    PreAuthorizedCode(Cow<'a, PreAuthorizedCodeGrant>),
}

/// Credential selection configuration in an Authorization Request.
pub struct CredentialRequestConfiguration<P: Profile> {
    /// Request credential by configuration and parameters.
    pub authorization_details: Vec<ProfileCredentialAuthorizationDetailsRequest<P>>,

    /// Request credential by scope.
    ///
    /// Credential Issuers *must* ignore unknown scope values in a request.
    pub scope: Option<ScopeBuf>,
}

impl<P: Profile> Default for CredentialRequestConfiguration<P> {
    fn default() -> Self {
        Self {
            authorization_details: Vec::new(),
            scope: None,
        }
    }
}

fn select_authorization_server<'a>(
    grant_authorization_server: Option<&'a Uri>,
    issuer: &'a Uri,
    issuer_authorization_servers: &'a [UriBuf],
) -> Result<&'a Uri, ClientError> {
    match grant_authorization_server {
        Some(url) => {
            if issuer_authorization_servers.iter().any(|u| u == url) {
                Ok(url)
            } else {
                Err(ClientError::InvalidAuthorizationServer)
            }
        }
        None => match issuer_authorization_servers.split_first() {
            Some((url, [])) => Ok(url),
            Some(_) => Err(ClientError::AmbiguousAuthorizationServer),
            None => Ok(issuer),
        },
    }
}

/// Simple OID4VCI client.
///
/// Uses the default methods implementations of [`Oid4vciClient`].
pub struct SimpleOid4vciClient<S = NoSigner, P = StandardProfile> {
    client_id: ClientIdBuf,
    public_jwk: Option<JWK>,
    signer: S,
    client_attestation: Option<JwsBuf>,
    profile: PhantomData<P>,
}

impl SimpleOid4vciClient {
    pub fn new(client_id: ClientIdBuf) -> Self {
        Self::new_with_profile(client_id, StandardProfile)
    }
}

impl<P: Profile> SimpleOid4vciClient<NoSigner, P> {
    pub fn new_with_profile(client_id: ClientIdBuf, profile: P) -> Self {
        std::mem::drop(profile); // It's just a marker.
        Self {
            client_id,
            public_jwk: None,
            signer: NoSigner,
            client_attestation: None,
            profile: PhantomData,
        }
    }
}

impl<S, P> SimpleOid4vciClient<S, P> {
    pub fn with_signer<T: JwsSigner>(self, signer: T) -> SimpleOid4vciClient<T, P> {
        SimpleOid4vciClient {
            client_id: self.client_id,
            public_jwk: self.public_jwk,
            signer,
            client_attestation: self.client_attestation,
            profile: self.profile,
        }
    }

    pub fn set_signer(&mut self, signer: S) {
        self.signer = signer;
    }

    pub fn with_public_jwk_opt(self, jwk: Option<JWK>) -> Self {
        Self {
            public_jwk: jwk,
            ..self
        }
    }

    pub fn with_public_jwk(self, jwk: JWK) -> Self {
        self.with_public_jwk_opt(Some(jwk))
    }

    pub fn set_public_jwk(&mut self, jwk: Option<JWK>) {
        self.public_jwk = jwk;
    }

    pub fn set_client_attestation(&mut self, client_attestation: Option<JwsBuf>) {
        self.client_attestation = client_attestation;
    }

    pub fn with_client_attestation_opt(self, client_attestation: Option<JwsBuf>) -> Self {
        Self {
            client_attestation,
            ..self
        }
    }

    pub fn with_client_attestation(self, client_attestation: JwsBuf) -> Self {
        self.with_client_attestation_opt(Some(client_attestation))
    }
}

impl<S: Clone, P> Clone for SimpleOid4vciClient<S, P> {
    fn clone(&self) -> Self {
        Self {
            client_id: self.client_id.clone(),
            public_jwk: self.public_jwk.clone(),
            signer: self.signer.clone(),
            client_attestation: self.client_attestation.clone(),
            profile: PhantomData,
        }
    }
}

impl<S, P> OAuth2Client for SimpleOid4vciClient<S, P>
where
    P: Profile,
{
    type TokenResponse = TokenResponse<String, Oid4vciTokenParams<P>>;

    fn client_id(&self) -> &ClientId {
        &self.client_id
    }
}

impl<S, P> Oid4vciClient for SimpleOid4vciClient<S, P>
where
    S: Clone + JwsSigner,
    P: Clone + Profile,
{
    type Profile = P;
}

impl<S, P> OAuth2DpopClient for SimpleOid4vciClient<S, P>
where
    S: Clone + JwsSigner,
    P: Profile,
{
    type Signer = S;

    fn dpop_signer(&self) -> &Self::Signer {
        &self.signer
    }

    fn dpop_public_jwk(&self) -> Option<&JWK> {
        self.public_jwk.as_ref()
    }
}

impl<S, P> AttestedOAuth2Client for SimpleOid4vciClient<S, P>
where
    S: Clone + JwsSigner,
    P: Profile,
{
    type Signer = S;

    fn attestation(&self) -> Option<&Jws> {
        self.client_attestation.as_deref()
    }

    fn attestation_pop_signer(&self) -> &Self::Signer {
        &self.signer
    }
}
