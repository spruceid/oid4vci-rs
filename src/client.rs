use std::marker::PhantomData;

use oauth2::{
    basic::{BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse},
    AccessToken, AuthUrl, AuthorizationCode, ClientId, CodeTokenRequest, CsrfToken, RedirectUrl,
    StandardRevocableToken, TokenUrl,
};
use openidconnect::{
    core::{
        CoreApplicationType, CoreClientAuthMethod, CoreGrantType, CoreJsonWebKey,
        CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseType,
        CoreSubjectIdentifierType, CoreTokenType,
    },
    registration::ClientMetadata,
    IssuerUrl, JsonWebKeyType, JweContentEncryptionAlgorithm, JweKeyManagementAlgorithm,
};
use serde::{Deserialize, Serialize};

use crate::{
    authorization::AuthorizationRequest,
    credential,
    metadata::{
        AuthorizationMetadata, CredentialMetadata, CredentialUrl, IssuerMetadata,
        IssuerMetadataDisplay,
    },
    profiles::{AuthorizationDetaislProfile, Profile},
    pushed_authorization::PushedAuthorizationRequest,
    token,
    types::{BatchCredentialUrl, DeferredCredentialUrl},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Pushed authorization request is not supported")]
    ParUnsupported(),
}

pub struct Client<C, JT, JE, JA>
where
    C: Profile,
    JT: JsonWebKeyType,
    JE: JweContentEncryptionAlgorithm<JT>,
    JA: JweKeyManagementAlgorithm,
{
    inner: oauth2::Client<
        BasicErrorResponse,
        token::Response,
        CoreTokenType,
        BasicTokenIntrospectionResponse,
        StandardRevocableToken,
        BasicRevocationErrorResponse,
    >,
    issuer: IssuerUrl,
    credential_endpoint: CredentialUrl,
    par_auth_url: Option<AuthUrl>,
    batch_credential_endpoint: Option<BatchCredentialUrl>,
    deferred_credential_endpoint: Option<DeferredCredentialUrl>,
    credential_response_encryption_alg_values_supported: Option<Vec<JA>>,
    credential_response_encryption_enc_values_supported: Option<Vec<JE>>,
    require_credential_response_encryption: Option<bool>,
    credentials_supported: Vec<CredentialMetadata<C::Metadata>>,
    display: Option<IssuerMetadataDisplay>,
    _phantom_jt: PhantomData<JT>,
}

impl<C, JT, JE, JA> Client<C, JT, JE, JA>
where
    C: Profile,
    JT: JsonWebKeyType,
    JE: JweContentEncryptionAlgorithm<JT>,
    JA: JweKeyManagementAlgorithm + Clone,
{
    pub fn new(
        client_id: ClientId,
        issuer: IssuerUrl,
        credential_endpoint: CredentialUrl,
        auth_url: AuthUrl,
        par_auth_url: Option<AuthUrl>,
        token_url: TokenUrl,
        redirect_uri: RedirectUrl,
    ) -> Self {
        let inner = oauth2::Client::new(client_id, None, auth_url, Some(token_url))
            .set_redirect_uri(redirect_uri);
        Self {
            inner,
            issuer,
            credential_endpoint,
            par_auth_url,
            batch_credential_endpoint: None,
            deferred_credential_endpoint: None,
            credential_response_encryption_alg_values_supported: None,
            credential_response_encryption_enc_values_supported: None,
            require_credential_response_encryption: None,
            credentials_supported: vec![],
            display: None,
            _phantom_jt: PhantomData,
        }
    }

    field_getters_setters![
        pub self [self] ["issuer metadata value"] {
            set_issuer -> issuer[IssuerUrl],
            set_credential_endpoint -> credential_endpoint[CredentialUrl],
            set_batch_credential_endpoint -> batch_credential_endpoint[Option<BatchCredentialUrl>],
            set_deferred_credential_endpoint -> deferred_credential_endpoint[Option<DeferredCredentialUrl>],
            set_credential_response_encryption_alg_values_supported -> credential_response_encryption_alg_values_supported[Option<Vec<JA>>],
            set_credential_response_encryption_enc_values_supported -> credential_response_encryption_enc_values_supported[Option<Vec<JE>>],
            set_require_credential_response_encryption -> require_credential_response_encryption[Option<bool>],
            set_credentials_supported -> credentials_supported[Vec<CredentialMetadata<C::Metadata>>],
            set_display -> display[Option<IssuerMetadataDisplay>],
        }
    ];

    pub fn from_issuer_metadata(
        issuer_metadata: IssuerMetadata<C::Metadata, JT, JE, JA>,
        authorization_metadata: AuthorizationMetadata,
        client_id: ClientId,
        redirect_uri: RedirectUrl,
    ) -> Self {
        Self::new(
            client_id,
            issuer_metadata.credential_issuer().clone(),
            issuer_metadata.credential_endpoint().clone(),
            authorization_metadata.authorization_endpoint().clone(),
            authorization_metadata
                .pushed_authorization_endpoint()
                .clone(),
            authorization_metadata.token_endpoint().clone(),
            redirect_uri,
        )
        .set_batch_credential_endpoint(issuer_metadata.batch_credential_endpoint().cloned())
        .set_deferred_credential_endpoint(issuer_metadata.deferred_credential_endpoint().cloned())
        .set_credential_response_encryption_alg_values_supported(
            issuer_metadata
                .credential_response_encryption_alg_values_supported()
                .cloned(),
        )
        .set_credential_response_encryption_enc_values_supported(
            issuer_metadata
                .credential_response_encryption_enc_values_supported()
                .cloned(),
        )
        .set_require_credential_response_encryption(
            issuer_metadata.require_credential_response_encryption(),
        )
        .set_credentials_supported(issuer_metadata.credentials_supported().clone())
        .set_display(issuer_metadata.display().cloned())
    }

    pub fn pushed_authorization_request<S, AD>(
        &self,
        state_fn: S,
    ) -> Result<PushedAuthorizationRequest<AD>, Error>
    where
        S: FnOnce() -> CsrfToken,
        AD: AuthorizationDetaislProfile,
    {
        if self.par_auth_url.is_none() {
            return Err(Error::ParUnsupported());
        }
        let inner = self.inner.authorize_url(state_fn);
        Ok(PushedAuthorizationRequest::new(
            inner,
            self.par_auth_url.clone().unwrap(),
            vec![],
            None,
            None,
            None,
        ))
    }

    pub fn pushed_authorize_url(&self, request_uri: String) -> String {
        let mut auth_url = self.inner.auth_url().url().clone();

        auth_url
            .query_pairs_mut()
            .append_pair("request_uri", &request_uri);

        auth_url
            .query_pairs_mut()
            .append_pair("client_id", &self.inner.client_id().to_string());

        auth_url.to_string()
    }

    pub fn authorize_url<S, AD>(&self, state_fn: S) -> AuthorizationRequest<AD>
    where
        S: FnOnce() -> CsrfToken,
        AD: AuthorizationDetaislProfile,
    {
        let inner = self.inner.authorize_url(state_fn);
        AuthorizationRequest::new(inner, vec![], None, None, None)
    }

    pub fn exchange_code(
        &self,
        code: AuthorizationCode,
    ) -> CodeTokenRequest<'_, token::Error, token::Response, CoreTokenType> {
        self.inner.exchange_code(code)
    }

    pub fn request_credential(
        &self,
        access_token: AccessToken,
        profile_fields: C::Credential,
    ) -> credential::RequestBuilder<C::Credential, JT, JE, JA> {
        let body = credential::Request::new(profile_fields);
        credential::RequestBuilder::new(body, self.credential_endpoint().clone(), access_token)
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
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseType,
    CoreSubjectIdentifierType,
>; // TODO
