use oauth2::{
    basic::{BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse},
    AccessToken, AuthUrl, AuthorizationCode, ClientId, CodeTokenRequest, CsrfToken, EndpointNotSet,
    EndpointSet, RedirectUrl, StandardRevocableToken, TokenUrl,
};
use openidconnect::{
    core::{
        CoreApplicationType, CoreClientAuthMethod, CoreGrantType, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreResponseType,
        CoreSubjectIdentifierType,
    },
    registration::ClientMetadata,
    IssuerUrl, JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm,
};
use serde::{Deserialize, Serialize};

use crate::{
    authorization::AuthorizationRequest,
    credential,
    credential_response_encryption::CredentialResponseEncryptionMetadata,
    metadata::{
        AuthorizationMetadata, CredentialIssuerMetadata, CredentialIssuerMetadataDisplay,
        CredentialMetadata, CredentialUrl,
    },
    profiles::{AuthorizationDetailsProfile, Profile},
    pushed_authorization::PushedAuthorizationRequest,
    token,
    types::{BatchCredentialUrl, DeferredCredentialUrl, ParUrl},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Pushed authorization request is not supported")]
    ParUnsupported(),

    #[error("Batch credential request is not supported")]
    BcrUnsupported(),
}

pub struct Client<C, JE, JA>
where
    C: Profile,
    JE: JweContentEncryptionAlgorithm,
    JA: JweKeyManagementAlgorithm + Clone,
{
    inner: oauth2::Client<
        BasicErrorResponse,
        token::Response,
        BasicTokenIntrospectionResponse,
        StandardRevocableToken,
        BasicRevocationErrorResponse,
        EndpointSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointSet,
    >,
    issuer: IssuerUrl,
    credential_endpoint: CredentialUrl,
    par_auth_url: Option<ParUrl>,
    batch_credential_endpoint: Option<BatchCredentialUrl>,
    deferred_credential_endpoint: Option<DeferredCredentialUrl>,
    credential_response_encryption: Option<CredentialResponseEncryptionMetadata<JE, JA>>,
    credential_configurations_supported: Vec<CredentialMetadata<C::Metadata>>,
    display: Option<Vec<CredentialIssuerMetadataDisplay>>,
}

impl<C, JE, JA> Client<C, JE, JA>
where
    C: Profile,
    JE: JweContentEncryptionAlgorithm,
    JA: JweKeyManagementAlgorithm + Clone,
{
    pub fn new(
        client_id: ClientId,
        issuer: IssuerUrl,
        credential_endpoint: CredentialUrl,
        auth_url: AuthUrl,
        par_auth_url: Option<ParUrl>,
        token_url: TokenUrl,
        redirect_uri: RedirectUrl,
    ) -> Self {
        let inner = oauth2::Client::new(client_id)
            .set_redirect_uri(redirect_uri)
            .set_auth_uri(auth_url)
            .set_token_uri(token_url);
        Self {
            inner,
            issuer,
            credential_endpoint,
            par_auth_url,
            batch_credential_endpoint: None,
            deferred_credential_endpoint: None,
            credential_response_encryption: None,
            credential_configurations_supported: vec![],
            display: None,
        }
    }

    field_getters_setters![
        pub self [self] ["issuer metadata value"] {
            set_issuer -> issuer[IssuerUrl],
            set_credential_endpoint -> credential_endpoint[CredentialUrl],
            set_batch_credential_endpoint -> batch_credential_endpoint[Option<BatchCredentialUrl>],
            set_deferred_credential_endpoint -> deferred_credential_endpoint[Option<DeferredCredentialUrl>],
            set_credential_response_encryption -> credential_response_encryption[Option<CredentialResponseEncryptionMetadata<JE, JA>>],
            set_credential_configurations_supported -> credential_configurations_supported[Vec<CredentialMetadata<C::Metadata>>],
            set_display -> display[Option<Vec<CredentialIssuerMetadataDisplay>>],
        }
    ];

    pub fn from_issuer_metadata(
        credential_issuer_metadata: CredentialIssuerMetadata<C::Metadata, JE, JA>,
        authorization_metadata: AuthorizationMetadata,
        client_id: ClientId,
        redirect_uri: RedirectUrl,
    ) -> Self {
        Self::new(
            client_id,
            credential_issuer_metadata.credential_issuer().clone(),
            credential_issuer_metadata.credential_endpoint().clone(),
            authorization_metadata.authorization_endpoint().clone(),
            authorization_metadata
                .pushed_authorization_endpoint()
                .clone(),
            authorization_metadata.token_endpoint().clone(),
            redirect_uri,
        )
        .set_batch_credential_endpoint(
            credential_issuer_metadata
                .batch_credential_endpoint()
                .cloned(),
        )
        .set_deferred_credential_endpoint(
            credential_issuer_metadata
                .deferred_credential_endpoint()
                .cloned(),
        )
        .set_credential_response_encryption(
            credential_issuer_metadata
                .credential_response_encryption()
                .cloned(),
        )
        .set_display(credential_issuer_metadata.display().cloned())
        .set_credential_configurations_supported(
            credential_issuer_metadata
                .credential_configurations_supported()
                .clone(),
        )
    }

    pub fn pushed_authorization_request<S, AD>(
        &self,
        state_fn: S,
    ) -> Result<PushedAuthorizationRequest<AD>, Error>
    where
        S: FnOnce() -> CsrfToken,
        AD: AuthorizationDetailsProfile,
    {
        if self.par_auth_url.is_none() {
            return Err(Error::ParUnsupported());
        }
        let inner = self.inner.authorize_url(state_fn);
        Ok(PushedAuthorizationRequest::new(
            inner,
            self.par_auth_url.clone().unwrap(),
            self.inner.auth_uri().clone(),
            vec![],
            None,
            None,
            None,
        ))
    }

    pub fn authorize_url<S, AD>(&self, state_fn: S) -> AuthorizationRequest<AD>
    where
        S: FnOnce() -> CsrfToken,
        AD: AuthorizationDetailsProfile,
    {
        let inner = self.inner.authorize_url(state_fn);
        AuthorizationRequest::new(inner, vec![], None, None, None)
    }

    pub fn exchange_code(
        &self,
        code: AuthorizationCode,
    ) -> CodeTokenRequest<'_, token::Error, token::Response> {
        self.inner.exchange_code(code)
    }

    pub fn request_credential(
        &self,
        access_token: AccessToken,
        profile_fields: C::Credential,
    ) -> credential::RequestBuilder<C::Credential, JE, JA> {
        let body = credential::Request::new(profile_fields);
        credential::RequestBuilder::new(body, self.credential_endpoint().clone(), access_token)
    }

    pub fn batch_request_credential(
        &self,
        access_token: AccessToken,
        profile_fields: Vec<C::Credential>,
    ) -> Result<credential::BatchRequestBuilder<C::Credential, JE, JA>, Error> {
        let endpoint = if let Some(endpoint) = self.batch_credential_endpoint() {
            endpoint
        } else {
            return Err(Error::BcrUnsupported());
        };
        let body = credential::BatchRequest::new(
            profile_fields
                .into_iter()
                .map(|pf| credential::Request::new(pf))
                .collect(),
        );
        Ok(credential::BatchRequestBuilder::new(
            body,
            endpoint.clone(),
            access_token,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AdditionalClientMetadata {
    credential_offer_endpoint: Option<CredentialUrl>,
}

impl openidconnect::registration::AdditionalClientMetadata for AdditionalClientMetadata {}

pub type Metadata = ClientMetadata<
    AdditionalClientMetadata,
    CoreApplicationType,
    CoreClientAuthMethod,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseType,
    CoreSubjectIdentifierType,
>; // TODO
