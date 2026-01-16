use std::marker::PhantomData;

use indexmap::IndexMap;
use iref::{Uri, UriBuf};
use oauth2::{
    basic::{BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse},
    AccessToken, AuthUrl, AuthorizationCode, ClientId, CodeTokenRequest, ConfigurationError,
    CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, RedirectUrl, StandardRevocableToken,
    TokenUrl,
};

use crate::{
    authorization::{
        pre_authorized_code::PreAuthorizedCodeTokenRequest,
        pushed_authorization::PushedAuthorizationRequest, server::AuthorizationServerMetadata,
        token, AuthorizationRequest,
    },
    batch::request::{BatchRequest, BatchRequestBuilder},
    encryption::CredentialResponseEncryptionMetadata,
    issuer::{
        metadata::{CredentialConfiguration, CredentialIssuerMetadataDisplay},
        CredentialIssuerMetadata,
    },
    profiles::Profile,
    request::{Request, RequestBuilder},
    types::{
        BatchCredentialUrl, CredentialConfigurationId, CredentialUrl, DeferredCredentialUrl,
        ParUrl, PreAuthorizedCode,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Batch Credential Request are not supported by this issuer")]
    BcrUnsupported,
    #[error("Pushed Authorization Requests are not supported by this issuer")]
    ParUnsupported,
    #[error("Authorization Requests are not supported by this issuer: {0}")]
    AuthUnsupported(ConfigurationError),
    #[error("An error occurred when discovering metadata: {0}")]
    MetadataDiscovery(anyhow::Error),
}

pub struct Client<C>
where
    C: Profile,
{
    inner: oauth2::Client<
        BasicErrorResponse,
        token::Response,
        BasicTokenIntrospectionResponse,
        StandardRevocableToken,
        BasicRevocationErrorResponse,
        EndpointMaybeSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointSet,
    >,
    issuer: UriBuf,
    credential_endpoint: CredentialUrl,
    par_auth_url: Option<ParUrl>,
    batch_credential_endpoint: Option<BatchCredentialUrl>,
    deferred_credential_endpoint: Option<DeferredCredentialUrl>,
    credential_response_encryption: Option<CredentialResponseEncryptionMetadata>,
    credential_configurations_supported:
        IndexMap<CredentialConfigurationId, CredentialConfiguration<C::CredentialConfiguration>>,
    display: Vec<CredentialIssuerMetadataDisplay>,
}

impl<C> Client<C>
where
    C: Profile,
{
    pub fn issuer(&self) -> &Uri {
        &self.issuer
    }

    pub fn set_issuer(&mut self, value: UriBuf) {
        self.issuer = value;
    }

    pub fn credential_endpoint(&self) -> &CredentialUrl {
        &self.credential_endpoint
    }

    pub fn set_credential_endpoint(&mut self, value: CredentialUrl) {
        self.credential_endpoint = value;
    }

    pub fn batch_credential_endpoint(&self) -> &Option<BatchCredentialUrl> {
        &self.batch_credential_endpoint
    }

    pub fn set_batch_credential_endpoint(&mut self, value: Option<BatchCredentialUrl>) {
        self.batch_credential_endpoint = value;
    }

    pub fn deferred_credential_endpoint(&self) -> &Option<DeferredCredentialUrl> {
        &self.deferred_credential_endpoint
    }

    pub fn set_deferred_credential_endpoint(&mut self, value: Option<DeferredCredentialUrl>) {
        self.deferred_credential_endpoint = value;
    }

    pub fn credential_response_encryption(&self) -> &Option<CredentialResponseEncryptionMetadata> {
        &self.credential_response_encryption
    }

    pub fn set_credential_response_encryption(
        &mut self,
        value: Option<CredentialResponseEncryptionMetadata>,
    ) {
        self.credential_response_encryption = value;
    }

    pub fn credential_configurations_supported(
        &self,
    ) -> &IndexMap<CredentialConfigurationId, CredentialConfiguration<C::CredentialConfiguration>>
    {
        &self.credential_configurations_supported
    }

    pub fn set_credential_configurations_supported(
        &mut self,
        value: IndexMap<
            CredentialConfigurationId,
            CredentialConfiguration<C::CredentialConfiguration>,
        >,
    ) {
        self.credential_configurations_supported = value;
    }

    pub fn display(&self) -> &Vec<CredentialIssuerMetadataDisplay> {
        &self.display
    }

    pub fn set_display(&mut self, value: Vec<CredentialIssuerMetadataDisplay>) {
        self.display = value;
    }

    pub fn from_issuer_metadata(
        client_id: ClientId,
        redirect_uri: RedirectUrl,
        credential_issuer_metadata: CredentialIssuerMetadata<C::CredentialConfiguration>,
        authorization_metadata: AuthorizationServerMetadata,
    ) -> Self {
        let inner = Self::new_inner_client(
            client_id,
            redirect_uri,
            authorization_metadata.authorization_endpoint.clone(),
            authorization_metadata.token_endpoint.clone(),
        );

        Self {
            inner,
            issuer: credential_issuer_metadata.credential_issuer.clone(),
            credential_endpoint: credential_issuer_metadata.credential_endpoint.clone(),
            par_auth_url: authorization_metadata
                .pushed_authorization_request_endpoint
                .clone(),
            batch_credential_endpoint: credential_issuer_metadata.batch_credential_endpoint.clone(),
            deferred_credential_endpoint: credential_issuer_metadata
                .deferred_credential_endpoint
                .clone(),
            credential_response_encryption: credential_issuer_metadata
                .credential_response_encryption
                .clone(),
            credential_configurations_supported: credential_issuer_metadata
                .credential_configurations_supported
                .clone(),
            display: credential_issuer_metadata.display.clone(),
        }
    }

    pub fn pushed_authorization_request<S>(
        &self,
        state_fn: S,
    ) -> Result<PushedAuthorizationRequest<'_>, Error>
    where
        S: FnOnce() -> CsrfToken,
    {
        let Some(par_url) = self.par_auth_url.as_ref() else {
            return Err(Error::ParUnsupported);
        };
        let inner = self.authorize_url(state_fn)?;
        Ok(PushedAuthorizationRequest::new(
            inner,
            par_url.clone(),
            self.inner
                .auth_uri()
                .cloned()
                .ok_or(Error::AuthUnsupported(ConfigurationError::MissingUrl(
                    "authorization",
                )))?,
        ))
    }

    pub fn authorize_url<S>(&self, state_fn: S) -> Result<AuthorizationRequest<'_>, Error>
    where
        S: FnOnce() -> CsrfToken,
    {
        let inner = self
            .inner
            .authorize_url(state_fn)
            .map_err(Error::AuthUnsupported)?;
        Ok(AuthorizationRequest::new(inner))
    }

    pub fn exchange_code(
        &self,
        code: AuthorizationCode,
    ) -> CodeTokenRequest<'_, BasicErrorResponse, token::Response> {
        self.inner.exchange_code(code)
    }

    pub fn exchange_pre_authorized_code(
        &self,
        pre_authorized_code: PreAuthorizedCode,
    ) -> PreAuthorizedCodeTokenRequest<'_, BasicErrorResponse, token::Response> {
        PreAuthorizedCodeTokenRequest {
            auth_type: self.inner.auth_type(),
            client_id: Some(self.inner.client_id()),
            client_secret: None,
            code: pre_authorized_code,
            extra_params: Vec::new(),
            token_url: self.inner.token_uri(),
            tx_code: None,
            _phantom: PhantomData,
        }
    }

    pub fn request_credential(
        &self,
        access_token: AccessToken,
        profile_fields: C::CredentialRequest,
    ) -> RequestBuilder<C::CredentialRequest> {
        let body = Request::new(profile_fields);
        RequestBuilder::new(body, self.credential_endpoint.clone(), access_token)
    }

    pub fn batch_request_credential(
        &self,
        access_token: AccessToken,
        profile_fields: Vec<C::CredentialRequest>,
    ) -> Result<BatchRequestBuilder<C::CredentialRequest>, Error> {
        let Some(endpoint) = &self.batch_credential_endpoint else {
            return Err(Error::BcrUnsupported);
        };
        let body = BatchRequest::new(profile_fields.into_iter().map(Request::new).collect());
        Ok(BatchRequestBuilder::new(
            body,
            endpoint.clone(),
            access_token,
        ))
    }

    fn new_inner_client(
        client_id: ClientId,
        redirect_uri: RedirectUrl,
        auth_url: Option<AuthUrl>,
        token_url: TokenUrl,
    ) -> oauth2::Client<
        BasicErrorResponse,
        token::Response,
        BasicTokenIntrospectionResponse,
        StandardRevocableToken,
        BasicRevocationErrorResponse,
        EndpointMaybeSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointSet,
    > {
        oauth2::Client::new(client_id)
            .set_redirect_uri(redirect_uri)
            .set_auth_uri_option(auth_url)
            .set_token_uri(token_url)
    }
}
