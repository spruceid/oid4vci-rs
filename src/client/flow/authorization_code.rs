use iref::{Uri, UriBuf};
use open_auth2::{
    endpoints::{
        authorization::AuthorizationEndpoint, pushed_authorization::PushedAuthorizationEndpoint,
        token::TokenEndpoint,
    },
    ext::{
        pkce::{
            AddPkceChallenge, AddPkceVerifier, PkceCodeChallengeAndMethod, PkceCodeVerifierBuf,
        },
        rar::AddAuthorizationDetails,
    },
    grant::authorization_code::ExchangeCode,
    transport::HttpClient,
    AddState, CodeBuf, ScopeBuf, State, StateBuf,
};

use crate::{
    authorization::{
        issuer_state::AddIssuerState,
        oauth2::{client_attestation::AddClientAttestation, dpop::AddDpop},
        server::Oid4vciAuthorizationServerMetadata,
    },
    client::{
        set_locations, ClientError, CredentialToken, Oid4vciClient, ResolvedCredentialOffer,
        SimpleOid4vciClient,
    },
};

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
    authorization_server_metadata: Oid4vciAuthorizationServerMetadata,
}

impl<C: Oid4vciClient> AuthorizationCodeRequired<C> {
    pub(crate) fn new(
        client: C,
        credential_offer: ResolvedCredentialOffer<C::Profile>,
        issuer_state: Option<String>,
        authorization_server_metadata: Oid4vciAuthorizationServerMetadata,
    ) -> Self {
        Self {
            client,
            credential_offer,
            issuer_state,
            authorization_server_metadata,
        }
    }

    pub async fn proceed(
        self,
        http_client: &impl HttpClient,
        client_redirect_url: UriBuf,
    ) -> Result<WaitingForAuthorizationCode<C>, ClientError> {
        let (pkce_code_challenge, pkce_code_verifier) =
            PkceCodeChallengeAndMethod::new_random_sha256();

        let mut configuration = self.client.configure_authorization_request(
            &self.credential_offer,
            &self.authorization_server_metadata,
        )?;

        set_locations(
            &self.credential_offer.issuer_metadata,
            &mut configuration.authorization_details,
        );

        let authorization_endpoint = AuthorizationEndpoint::new(
            &self.client,
            self.authorization_server_metadata
                .authorization_endpoint
                .as_deref()
                .ok_or(ClientError::MissingAuthorizationEndpoint)?,
        );

        let state = StateBuf::new_random();

        let server_redirect_url = match &self
            .authorization_server_metadata
            .extra
            .pushed_authorization_request_endpoint
        {
            Some(par_endpoint_url) => {
                let par_endpoint = PushedAuthorizationEndpoint::new(&self.client, par_endpoint_url);

                par_endpoint
                    .authorize_url(
                        Some(client_redirect_url.clone()),
                        configuration.scope.clone(),
                    )
                    .with_state(Some(state.clone()))
                    .with_issuer_state(self.issuer_state.as_deref())
                    .with_authorization_details(&configuration.authorization_details)
                    .with_pkce_challenge(pkce_code_challenge)
                    .with_client_attestation(&self.authorization_server_metadata)
                    .with_dpop(None, None)
                    .send(http_client)
                    .await?
                    .for_endpoint(&authorization_endpoint)
            }
            None => authorization_endpoint
                .authorize_url(
                    Some(client_redirect_url.to_owned()),
                    configuration.scope.clone(),
                )
                .with_state(Some(state.clone()))
                .with_issuer_state(self.issuer_state.as_deref())
                .with_authorization_details(&configuration.authorization_details)
                .with_pkce_challenge(pkce_code_challenge)
                .with_client_attestation(&self.authorization_server_metadata)
                .with_dpop(None, None)
                .into_redirect_uri(),
        };

        Ok(WaitingForAuthorizationCode {
            client: self.client,
            credential_offer: self.credential_offer,
            authorization_server_metadata: self.authorization_server_metadata,
            requested_scope: configuration.scope,
            pkce_code_verifier,
            client_redirect_url: Some(client_redirect_url),
            server_redirect_url,
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
    authorization_server_metadata: Oid4vciAuthorizationServerMetadata,
    requested_scope: Option<ScopeBuf>,
    pkce_code_verifier: PkceCodeVerifierBuf,
    client_redirect_url: Option<UriBuf>,
    server_redirect_url: UriBuf,
    state: StateBuf,
}

impl<C: Oid4vciClient> WaitingForAuthorizationCode<C> {
    pub fn redirect_url(&self) -> &Uri {
        &self.server_redirect_url
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub async fn proceed(
        self,
        http_client: &impl HttpClient,
        authorization_code: CodeBuf,
    ) -> Result<CredentialToken<C::Profile>, ClientError> {
        let mut authorization_details = self
            .client
            .configure_token_request(&self.credential_offer)?;

        set_locations(
            &self.credential_offer.issuer_metadata,
            &mut authorization_details,
        );

        let token_endpoint = TokenEndpoint::new(
            &self.client,
            self.authorization_server_metadata
                .token_endpoint
                .as_deref()
                .ok_or(ClientError::MissingTokenEndpoint)?,
        );

        let response = token_endpoint
            .exchange_code(authorization_code, self.client_redirect_url)
            .with_authorization_details(&authorization_details)
            .with_pkce_verifier(&self.pkce_code_verifier)
            .with_client_attestation(&self.authorization_server_metadata)
            .with_dpop(None, None)
            .send(&http_client)
            .await?;

        Ok(CredentialToken {
            credential_offer: self.credential_offer,
            authorization_server_metadata: self.authorization_server_metadata,
            requested_scope: self.requested_scope,
            response,
        })
    }
}
