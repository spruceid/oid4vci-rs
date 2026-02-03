use std::{borrow::Cow, marker::PhantomData};

use iref::{Uri, UriBuf};
use oauth2::{
    basic::{BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse},
    http::{Method, StatusCode},
    url::Url,
    AccessToken, AsyncHttpClient, AuthorizationCode, ClientId, CsrfToken, EndpointNotSet,
    EndpointSet, HttpRequest, HttpResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    Scope, StandardRevocableToken, SyncHttpClient, TokenResponse,
};

use crate::{
    authorization::{
        authorization_details::{
            CredentialAuthorizationDetailsRequest, CredentialAuthorizationParams,
            TokenRequestAuthorizationDetails,
        },
        pre_authorized_code::PreAuthorizedCodeClient,
        pushed_authorization::OAuth2PushAuthorizationClient,
        request::Oid4vciAuthorizationRequest,
        server::AuthorizationServerMetadata,
        token::{self, CredentialTokenResponse},
    },
    issuer::{
        metadata::{CredentialConfiguration, CredentialFormatMetadata},
        CredentialIssuerMetadata,
    },
    nonce::NonceResponse,
    offer::{
        AuthorizationCodeGrant, CredentialOfferError, CredentialOfferParameters,
        PreAuthorizedCodeGrant, TxCodeDefinition,
    },
    profile::{
        ProfileCredentialAuthorizationDetailsRequest,
        ProfileCredentialAuthorizationDetailsResponse, ProfileCredentialIssuerMetadata,
        ProfileCredentialResponse,
    },
    proof::Proofs,
    request::{CredentialOrConfigurationId, CredentialOrConfigurationIdRef, CredentialRequest},
    util::{
        discoverable::Discoverable,
        http::{check_content_type, HttpError, MIME_TYPE_JSON},
    },
    CredentialOffer, Profile, StandardProfile,
};

/// OID4VCI client.
///
/// Unless you need custom ways of configuring authorization and token requests,
/// you probably want to use the [`SimpleOid4vciClient`] implementation
/// directly.
pub trait Oid4vciClient: Clone {
    /// OID4VCI profile.
    type Profile: Profile;

    /// Returns the OAuth2 client identifier.
    fn client_id(&self) -> &ClientId;

    /// Configures the credentials requested for issuance in an Authorization
    /// Request.
    ///
    /// Implementors do not need to set the `locations` value of the
    /// authorization details manually.
    fn configure_authorization_request(
        &self,
        offer: &ResolvedCredentialOffer<Self::Profile>,
        _authorization_server_metadata: &AuthorizationServerMetadata,
    ) -> Result<CredentialRequestConfiguration<Self::Profile>, ClientError> {
        let mut result = CredentialRequestConfiguration::default();

        for id in &offer.params.credential_configuration_ids {
            if let Some(conf) = offer
                .issuer_metadata
                .credential_configurations_supported
                .get(id)
            {
                if let Some(scope) = &conf.scope {
                    result.scopes.push(scope.clone());
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
    async fn resolve_offer_async<C>(
        &self,
        http_client: &C,
        credential_offer: CredentialOffer,
    ) -> Result<ResolvedCredentialOffer<Self::Profile>, ClientError>
    where
        C: ?Sized + for<'c> AsyncHttpClient<'c>,
    {
        let params = credential_offer.resolve_async(http_client).await?;

        let issuer_metadata =
            CredentialIssuerMetadata::<<Self::Profile as Profile>::FormatMetadata>::discover_async(
                http_client,
                &params.credential_issuer,
            )
            .await?;

        Ok(ResolvedCredentialOffer {
            params,
            issuer_metadata,
        })
    }

    /// Resolves a credential offer, fetching its parameter and issuer metadata.
    fn resolve_offer(
        &self,
        http_client: &(impl ?Sized + SyncHttpClient),
        credential_offer: CredentialOffer,
    ) -> Result<ResolvedCredentialOffer<Self::Profile>, ClientError> {
        let params = credential_offer.resolve(http_client)?;

        let issuer_metadata =
            CredentialIssuerMetadata::<<Self::Profile as Profile>::FormatMetadata>::discover(
                http_client,
                &params.credential_issuer,
            )?;

        Ok(ResolvedCredentialOffer {
            params,
            issuer_metadata,
        })
    }

    /// Process a credential offer.
    #[allow(async_fn_in_trait)]
    async fn accept_offer_async<C>(
        &self,
        http_client: &C,
        credential_offer: ResolvedCredentialOffer<Self::Profile>,
    ) -> Result<CredentialTokenState<Self>, ClientError>
    where
        C: ?Sized + for<'c> AsyncHttpClient<'c>,
    {
        match self.select_grant(&credential_offer.params)? {
            GrantSelection::AuthorizationCode(grant) => {
                let authorization_server_url = select_authorization_server(
                    grant.authorization_server.as_deref(),
                    &credential_offer.params.credential_issuer,
                    &credential_offer.issuer_metadata.authorization_servers,
                )?;

                let authorization_server_metadata = AuthorizationServerMetadata::discover_async(
                    http_client,
                    authorization_server_url,
                )
                .await?;

                let issuer_state = grant.issuer_state.clone();

                Ok(CredentialTokenState::RequiresAuthorizationCode(
                    AuthorizationCodeRequired {
                        client: self.clone(),
                        credential_offer,
                        issuer_state,
                        authorization_server_metadata,
                    },
                ))
            }
            GrantSelection::PreAuthorizedCode(grant) => {
                let authorization_server_url = select_authorization_server(
                    grant.authorization_server.as_deref(),
                    &credential_offer.params.credential_issuer,
                    &credential_offer.issuer_metadata.authorization_servers,
                )?;

                let authorization_server_metadata = AuthorizationServerMetadata::discover_async(
                    http_client,
                    authorization_server_url,
                )
                .await?;

                let oauth2_client: OAuth2PreAuthClient<Self::Profile> =
                    oauth2::Client::new(self.client_id().clone())
                        .set_token_uri(authorization_server_metadata.token_endpoint);

                match grant.tx_code.clone() {
                    Some(tx_code_definition) => {
                        let pre_authorized_code = grant.pre_authorized_code.clone();

                        Ok(CredentialTokenState::RequiresTxCode(TxCodeRequired {
                            credential_offer,
                            oauth2_client,
                            pre_authorized_code,
                            tx_code_definition,
                        }))
                    }
                    None => {
                        let mut authorization_details =
                            self.configure_token_request(&credential_offer)?;

                        set_locations(
                            &credential_offer.issuer_metadata,
                            &mut authorization_details,
                        );

                        let response = oauth2_client
                            .exchange_pre_authorized_code(&grant.pre_authorized_code)
                            .set_anonymous_client_if(
                                authorization_server_metadata
                                    .pre_authorized_grant_anonymous_access_supported,
                            )
                            .set_authorization_details(&authorization_details)
                            .request_async(http_client)
                            .await
                            .map_err(|_| ClientError::Authorization)?;

                        Ok(CredentialTokenState::Ready(CredentialToken {
                            credential_offer,
                            requested_scopes: Vec::new(),
                            response,
                        }))
                    }
                }
            }
        }
    }

    /// Process a credential offer.
    fn accept_offer(
        &self,
        http_client: &impl SyncHttpClient,
        credential_offer: ResolvedCredentialOffer<Self::Profile>,
    ) -> Result<CredentialTokenState<Self>, ClientError> {
        match self.select_grant(&credential_offer.params)? {
            GrantSelection::AuthorizationCode(grant) => {
                let authorization_server_url = select_authorization_server(
                    grant.authorization_server.as_deref(),
                    &credential_offer.params.credential_issuer,
                    &credential_offer.issuer_metadata.authorization_servers,
                )?;

                let authorization_server_metadata =
                    AuthorizationServerMetadata::discover(http_client, authorization_server_url)?;

                let issuer_state = grant.issuer_state.clone();

                Ok(CredentialTokenState::RequiresAuthorizationCode(
                    AuthorizationCodeRequired {
                        client: self.clone(),
                        credential_offer,
                        issuer_state,
                        authorization_server_metadata,
                    },
                ))
            }
            GrantSelection::PreAuthorizedCode(grant) => {
                let authorization_server_url = select_authorization_server(
                    grant.authorization_server.as_deref(),
                    &credential_offer.params.credential_issuer,
                    &credential_offer.issuer_metadata.authorization_servers,
                )?;

                let authorization_server_metadata =
                    AuthorizationServerMetadata::discover(http_client, authorization_server_url)?;

                let oauth2_client: OAuth2PreAuthClient<Self::Profile> =
                    oauth2::Client::new(self.client_id().clone())
                        .set_token_uri(authorization_server_metadata.token_endpoint);

                match grant.tx_code.clone() {
                    Some(tx_code_definition) => {
                        let pre_authorized_code = grant.pre_authorized_code.clone();

                        Ok(CredentialTokenState::RequiresTxCode(TxCodeRequired {
                            credential_offer,
                            oauth2_client,
                            pre_authorized_code,
                            tx_code_definition,
                        }))
                    }
                    None => {
                        let mut authorization_details =
                            self.configure_token_request(&credential_offer)?;

                        set_locations(
                            &credential_offer.issuer_metadata,
                            &mut authorization_details,
                        );

                        let response = oauth2_client
                            .exchange_pre_authorized_code(&grant.pre_authorized_code)
                            .set_anonymous_client_if(
                                authorization_server_metadata
                                    .pre_authorized_grant_anonymous_access_supported,
                            )
                            .set_authorization_details(&authorization_details)
                            .request(http_client)
                            .map_err(|_| ClientError::Authorization)?;

                        Ok(CredentialTokenState::Ready(CredentialToken {
                            credential_offer,
                            requested_scopes: Vec::new(),
                            response,
                        }))
                    }
                }
            }
        }
    }

    #[allow(async_fn_in_trait)]
    async fn exchange_credential_async<H>(
        &self,
        http_client: &H,
        token: &CredentialToken<Self::Profile>,
        credential: CredentialOrConfigurationId,
        proofs: Option<Proofs>,
    ) -> Result<ProfileCredentialResponse<Self::Profile>, ClientError>
    where
        H: ?Sized + for<'c> AsyncHttpClient<'c>,
        <Self::Profile as Profile>::RequestParams: Default,
    {
        self.exchange_credential_with_async(
            http_client,
            token,
            credential,
            proofs,
            Default::default(),
        )
        .await
    }

    #[allow(async_fn_in_trait)]
    async fn exchange_credential_with_async<H>(
        &self,
        http_client: &H,
        token: &CredentialToken<Self::Profile>,
        credential: CredentialOrConfigurationId,
        proofs: Option<Proofs>,
        params: <Self::Profile as Profile>::RequestParams,
    ) -> Result<ProfileCredentialResponse<Self::Profile>, ClientError>
    where
        H: ?Sized + for<'c> AsyncHttpClient<'c>,
    {
        let request = CredentialRequest {
            credential,
            proofs,
            credential_response_encryption: None, // TODO support encryption
            params,
        };

        request
            .send_async(
                http_client,
                &token.credential_offer.issuer_metadata.credential_endpoint,
                token.get(),
            )
            .await
            .map_err(Into::into)
    }

    /// Exchange a Credential Token against one or more Credential(s).
    fn exchange_credential(
        &self,
        http_client: &impl SyncHttpClient,
        token: &CredentialToken<Self::Profile>,
        credential: CredentialOrConfigurationId,
        proofs: Option<Proofs>,
    ) -> Result<ProfileCredentialResponse<Self::Profile>, ClientError>
    where
        <Self::Profile as Profile>::RequestParams: Default,
    {
        self.exchange_credential_with(http_client, token, credential, proofs, Default::default())
    }

    /// Exchange a Credential Token against one or more Credential(s), with
    /// custom request parameters.
    fn exchange_credential_with(
        &self,
        http_client: &impl SyncHttpClient,
        token: &CredentialToken<Self::Profile>,
        credential: CredentialOrConfigurationId,
        proofs: Option<Proofs>,
        params: <Self::Profile as Profile>::RequestParams,
    ) -> Result<ProfileCredentialResponse<Self::Profile>, ClientError> {
        let request = CredentialRequest {
            credential,
            proofs,
            credential_response_encryption: None, // TODO support encryption
            params,
        };

        request
            .send(
                http_client,
                &token.credential_offer.issuer_metadata.credential_endpoint,
                token.get(),
            )
            .map_err(Into::into)
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
    pub scopes: Vec<Scope>,
}

impl<P: Profile> Default for CredentialRequestConfiguration<P> {
    fn default() -> Self {
        Self {
            authorization_details: Vec::new(),
            scopes: Vec::new(),
        }
    }
}

/// Resolved Credential Offer.
///
/// Contains the credential offer parameters and issuer metadata, fetched from
/// the initial offer.
///
/// Can be used with [`Oid4vciClient::accept_offer`] to get a
/// [`CredentialToken`].
#[derive(Debug)]
pub struct ResolvedCredentialOffer<P: Profile = StandardProfile> {
    pub params: CredentialOfferParameters,
    pub issuer_metadata: ProfileCredentialIssuerMetadata<P>,
}

impl<P: Profile> Clone for ResolvedCredentialOffer<P> {
    fn clone(&self) -> Self {
        Self {
            params: self.params.clone(),
            issuer_metadata: self.issuer_metadata.clone(),
        }
    }
}

/// Credential Token.
///
/// Stores the necessary information to query a credential through the
/// [`Oid4vciClient::query_credential`] method.
///
/// You can use the [`Self::get_nonce`] method to query a nonce value from the
/// server, to use with proof of possessions.
pub struct CredentialToken<P: Profile = StandardProfile> {
    credential_offer: ResolvedCredentialOffer<P>,
    requested_scopes: Vec<Scope>,
    response: CredentialTokenResponse<<P as Profile>::AuthorizationParams>,
}

impl<P: Profile> CredentialToken<P> {
    pub fn get(&self) -> &AccessToken {
        self.response.access_token()
    }

    pub fn credential_issuer(&self) -> &Uri {
        &self.credential_offer.params.credential_issuer
    }

    pub fn credential_offer(&self) -> &ResolvedCredentialOffer<P> {
        &self.credential_offer
    }

    pub fn scopes(&self) -> &[Scope] {
        self.response
            .scopes()
            .map(Vec::as_slice)
            .unwrap_or(&self.requested_scopes)
    }

    pub fn authorization_details(&self) -> &[ProfileCredentialAuthorizationDetailsResponse<P>] {
        &self.response.extra_fields().authorization_details
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
                .extra_fields()
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

    pub async fn get_nonce_async<C>(&self, http_client: &C) -> Result<Option<String>, ClientError>
    where
        C: for<'c> AsyncHttpClient<'c>,
    {
        match self.nonce_request() {
            Some((uri, request)) => {
                let response = http_client
                    .call(request)
                    .await
                    .map_err(HttpError::query(uri))?;
                self.process_nonce_response(uri, response)
                    .map(|r| Some(r.c_nonce))
                    .map_err(Into::into)
            }
            None => Ok(None),
        }
    }

    pub fn get_nonce<C>(&self, http_client: &C) -> Result<Option<String>, ClientError>
    where
        C: SyncHttpClient,
    {
        match self.nonce_request() {
            Some((uri, request)) => {
                let response = http_client.call(request).map_err(HttpError::query(uri))?;
                self.process_nonce_response(uri, response)
                    .map(|r| Some(r.c_nonce))
                    .map_err(Into::into)
            }
            None => Ok(None),
        }
    }

    fn nonce_request(&self) -> Option<(&Uri, HttpRequest)> {
        let url = self
            .credential_offer
            .issuer_metadata
            .nonce_endpoint
            .as_deref()?;
        let mut request = HttpRequest::new(Vec::new());
        *request.method_mut() = Method::POST;
        *request.uri_mut() = url.as_str().parse().unwrap();
        Some((url, request))
    }

    fn process_nonce_response(
        &self,
        uri: &Uri,
        response: HttpResponse,
    ) -> Result<NonceResponse, HttpError> {
        let status = response.status();
        if status != StatusCode::OK {
            return Err(HttpError::ServerError(uri.to_owned(), status));
        }

        check_content_type(uri, response.headers(), MIME_TYPE_JSON)?;
        serde_json::from_slice(response.body()).map_err(HttpError::json(uri))
    }
}

/// Credential Token State.
///
/// When querying a Credential Authorization Token to the Authorization Server,
/// it may ask for further authentication. This can be either querying an
/// Authorization Code, or a Transaction Code for Pre-Authorized Code grants.
/// If the Pre-Authorized Code grant doesn't require a Transaction Code, the
/// token will directly be `Ready`.
pub enum CredentialTokenState<C: Oid4vciClient = SimpleOid4vciClient> {
    /// Credential Token requires an Authorization Code.
    RequiresAuthorizationCode(AuthorizationCodeRequired<C>),

    /// Credential Token requires a Transaction Code.
    RequiresTxCode(TxCodeRequired<C::Profile>),

    /// Credential Token is ready.
    Ready(CredentialToken<C::Profile>),
}

pub struct TxCodeRequired<P: Profile = StandardProfile> {
    credential_offer: ResolvedCredentialOffer<P>,
    oauth2_client: OAuth2PreAuthClient<P>,
    pre_authorized_code: String,
    tx_code_definition: TxCodeDefinition,
}

impl<P: Profile> TxCodeRequired<P> {
    pub fn tx_code_definition(&self) -> &TxCodeDefinition {
        &self.tx_code_definition
    }

    pub async fn proceed_async<'c>(
        self,
        http_client: &'c impl AsyncHttpClient<'c>,
        tx_code: &str,
    ) -> Result<CredentialToken<P>, ClientError> {
        let response = self
            .oauth2_client
            .exchange_pre_authorized_code(&self.pre_authorized_code)
            .set_tx_code(tx_code)
            .request_async(http_client)
            .await
            .map_err(|_| ClientError::Authorization)?;

        Ok(CredentialToken {
            credential_offer: self.credential_offer,
            requested_scopes: Vec::new(),
            response,
        })
    }

    pub fn proceed(
        self,
        http_client: &impl SyncHttpClient,
        tx_code: &str,
    ) -> Result<CredentialToken<P>, ClientError> {
        let response = self
            .oauth2_client
            .exchange_pre_authorized_code(&self.pre_authorized_code)
            .set_tx_code(tx_code)
            .request(http_client)
            .map_err(|_| ClientError::Authorization)?;

        Ok(CredentialToken {
            credential_offer: self.credential_offer,
            requested_scopes: Vec::new(),
            response,
        })
    }
}

/// Credential Token is protected behind an Authorization Code.
///
/// This type holds the necessary information to perform Authorization and then
/// resume the Credential Token query.
///
/// You can get a redirect URL by calling the [`Self::proceed`] method, then
/// redirect the user agent. Once the application gets the Authorization Code,
/// you can proceed with the query by calling
/// [`WaitingForAuthorizationCode::proceed`].
pub struct AuthorizationCodeRequired<C: Oid4vciClient = SimpleOid4vciClient> {
    client: C,
    credential_offer: ResolvedCredentialOffer<C::Profile>,
    issuer_state: Option<String>,
    authorization_server_metadata: AuthorizationServerMetadata,
}

impl<C: Oid4vciClient> AuthorizationCodeRequired<C> {
    pub async fn proceed_async<'c>(
        self,
        http_client: &'c impl AsyncHttpClient<'c>,
        redirect_url: RedirectUrl,
    ) -> Result<WaitingForAuthorizationCode<C>, ClientError> {
        let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut configuration = self.client.configure_authorization_request(
            &self.credential_offer,
            &self.authorization_server_metadata,
        )?;

        let oauth2_client: OAuth2AuthCodeClient<C::Profile> =
            oauth2::Client::new(self.client.client_id().clone())
                .set_redirect_uri(redirect_url)
                .set_auth_uri(
                    self.authorization_server_metadata
                        .authorization_endpoint
                        .ok_or(ClientError::MissingAuthorizationEndpoint)?,
                )
                .set_token_uri(self.authorization_server_metadata.token_endpoint);

        set_locations(
            &self.credential_offer.issuer_metadata,
            &mut configuration.authorization_details,
        );

        let (redirect_url, state) = match &self
            .authorization_server_metadata
            .pushed_authorization_request_endpoint
        {
            Some(par_endpoint_url) => {
                oauth2_client
                    .push_authorize_url(par_endpoint_url, CsrfToken::new_random)
                    .add_scopes(configuration.scopes.iter().cloned())
                    .set_authorization_details(configuration.authorization_details)
                    .set_issuer_state_option(self.issuer_state.as_deref())
                    .set_pkce_challenge(pkce_code_challenge)
                    .request_async(http_client)
                    .await?
            }
            None => oauth2_client
                .authorize_url(CsrfToken::new_random)
                .add_scopes(configuration.scopes.iter().cloned())
                .set_authorization_details(configuration.authorization_details)
                .set_issuer_state_option(self.issuer_state.as_deref())
                .set_pkce_challenge(pkce_code_challenge)
                .url(),
        };

        Ok(WaitingForAuthorizationCode {
            client: self.client,
            oauth2_client,
            credential_offer: self.credential_offer,
            requested_scopes: configuration.scopes,
            pkce_code_verifier,
            redirect_url,
            state,
        })
    }

    pub fn proceed(
        self,
        http_client: &impl SyncHttpClient,
        redirect_url: RedirectUrl,
    ) -> Result<WaitingForAuthorizationCode<C>, ClientError> {
        let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut configuration = self.client.configure_authorization_request(
            &self.credential_offer,
            &self.authorization_server_metadata,
        )?;

        let oauth2_client: OAuth2AuthCodeClient<C::Profile> =
            oauth2::Client::new(self.client.client_id().clone())
                .set_redirect_uri(redirect_url)
                .set_auth_uri(
                    self.authorization_server_metadata
                        .authorization_endpoint
                        .ok_or(ClientError::MissingAuthorizationEndpoint)?,
                )
                .set_token_uri(self.authorization_server_metadata.token_endpoint);

        set_locations(
            &self.credential_offer.issuer_metadata,
            &mut configuration.authorization_details,
        );

        let (redirect_url, state) = match &self
            .authorization_server_metadata
            .pushed_authorization_request_endpoint
        {
            Some(par_endpoint_url) => oauth2_client
                .push_authorize_url(par_endpoint_url, CsrfToken::new_random)
                .add_scopes(configuration.scopes.iter().cloned())
                .set_authorization_details(configuration.authorization_details)
                .set_issuer_state_option(self.issuer_state.as_deref())
                .set_pkce_challenge(pkce_code_challenge)
                .request(http_client)?,
            None => oauth2_client
                .authorize_url(CsrfToken::new_random)
                .add_scopes(configuration.scopes.iter().cloned())
                .set_authorization_details(configuration.authorization_details)
                .set_issuer_state_option(self.issuer_state.as_deref())
                .set_pkce_challenge(pkce_code_challenge)
                .url(),
        };

        Ok(WaitingForAuthorizationCode {
            client: self.client,
            oauth2_client,
            credential_offer: self.credential_offer,
            requested_scopes: configuration.scopes,
            pkce_code_verifier,
            redirect_url,
            state,
        })
    }
}

/// Waiting for an Authorization Code.
///
/// Holds the necessary information to proceed with the Credential Request when
/// the Authorization Code is received.
pub struct WaitingForAuthorizationCode<C: Oid4vciClient = SimpleOid4vciClient> {
    client: C,
    credential_offer: ResolvedCredentialOffer<C::Profile>,
    oauth2_client: OAuth2AuthCodeClient<C::Profile>,
    requested_scopes: Vec<Scope>,
    pkce_code_verifier: PkceCodeVerifier,
    redirect_url: Url,
    state: CsrfToken,
}

impl<C: Oid4vciClient> WaitingForAuthorizationCode<C> {
    pub fn redirect_url(&self) -> &Url {
        &self.redirect_url
    }

    pub fn state(&self) -> &CsrfToken {
        &self.state
    }

    pub async fn proceed_async<H>(
        self,
        http_client: &H,
        authorization_code: AuthorizationCode,
    ) -> Result<CredentialToken<C::Profile>, ClientError>
    where
        H: for<'c> AsyncHttpClient<'c>,
    {
        let mut authorization_details = self
            .client
            .configure_token_request(&self.credential_offer)?;

        set_locations(
            &self.credential_offer.issuer_metadata,
            &mut authorization_details,
        );

        let response = self
            .oauth2_client
            .exchange_code(authorization_code)
            .set_authorization_details(&authorization_details)
            .set_pkce_verifier(self.pkce_code_verifier)
            .request_async(http_client)
            .await
            .map_err(|_| ClientError::Authorization)?;

        Ok(CredentialToken {
            credential_offer: self.credential_offer,
            requested_scopes: self.requested_scopes,
            response,
        })
    }

    pub fn proceed<H>(
        self,
        http_client: &H,
        authorization_code: AuthorizationCode,
    ) -> Result<CredentialToken<C::Profile>, ClientError>
    where
        H: SyncHttpClient,
    {
        let mut authorization_details = self
            .client
            .configure_token_request(&self.credential_offer)?;

        set_locations(
            &self.credential_offer.issuer_metadata,
            &mut authorization_details,
        );

        let response = self
            .oauth2_client
            .exchange_code(authorization_code)
            .set_authorization_details(&authorization_details)
            .set_pkce_verifier(self.pkce_code_verifier)
            .request(http_client)
            .map_err(|_| ClientError::Authorization)?;

        Ok(CredentialToken {
            credential_offer: self.credential_offer,
            requested_scopes: self.requested_scopes,
            response,
        })
    }
}

/// Client error.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Error with the credential offer.
    #[error(transparent)]
    CredentialOffer(#[from] CredentialOfferError),

    /// The credential offer doesn't have any grant, and the client doesn't
    /// have any built-in grant.
    #[error("missing grant")]
    MissingGrant,

    #[error(transparent)]
    Http(#[from] HttpError),

    #[error("missing authorization server")]
    MissingAuthorizationServer,

    #[error("ambiguous authorization server")]
    AmbiguousAuthorizationServer,

    #[error("invalid authorization server")]
    InvalidAuthorizationServer,

    #[error("missing authorization endpoint")]
    MissingAuthorizationEndpoint,

    #[error("authorization failed")]
    Authorization,

    /// The wallet is lost and doesn't know what credential to pick.
    #[error("ambiguous credential offer")]
    AmbiguousCredentialOffer,

    #[error("{0}")]
    Other(String),
}

/// Inner OAuth2 client.
type OAuth2AuthCodeClient<P> = oauth2::Client<
    BasicErrorResponse,
    token::CredentialTokenResponse<<P as Profile>::AuthorizationParams>,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

/// Inner OAuth2 client.
type OAuth2PreAuthClient<P> = oauth2::Client<
    BasicErrorResponse,
    token::CredentialTokenResponse<<P as Profile>::AuthorizationParams>,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

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
pub struct SimpleOid4vciClient<P = StandardProfile> {
    client_id: ClientId,
    profile: PhantomData<P>,
}

impl<P> Clone for SimpleOid4vciClient<P> {
    fn clone(&self) -> Self {
        Self {
            client_id: self.client_id.clone(),
            profile: PhantomData,
        }
    }
}

impl SimpleOid4vciClient {
    pub fn new(client_id: ClientId) -> Self {
        Self::new_with_profile(client_id, StandardProfile)
    }
}

impl<P: Profile> SimpleOid4vciClient<P> {
    pub fn new_with_profile(client_id: ClientId, profile: P) -> Self {
        std::mem::drop(profile); // It's just a marker.
        Self {
            client_id,
            profile: PhantomData,
        }
    }
}

impl<P: Profile> Oid4vciClient for SimpleOid4vciClient<P> {
    type Profile = P;

    fn client_id(&self) -> &ClientId {
        &self.client_id
    }
}
