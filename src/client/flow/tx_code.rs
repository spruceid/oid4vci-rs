use open_auth2::{endpoints::token::TokenEndpoint, transport::HttpClient};

use crate::{
    authorization::{
        oauth2::{client_attestation::AddClientAttestation, dpop::AddDpop},
        server::Oid4vciAuthorizationServerMetadata,
    },
    client::{ClientError, CredentialToken, Oid4vciClient, ResolvedCredentialOffer},
    offer::TxCodeDefinition,
};

pub struct TxCodeRequired<C: Oid4vciClient> {
    client: C,
    credential_offer: ResolvedCredentialOffer<C::Profile>,
    authorization_server_metadata: Oid4vciAuthorizationServerMetadata,
    pre_authorized_code: String,
    tx_code_definition: TxCodeDefinition,
}

impl<C: Oid4vciClient> TxCodeRequired<C> {
    pub(crate) fn new(
        client: C,
        credential_offer: ResolvedCredentialOffer<C::Profile>,
        authorization_server_metadata: Oid4vciAuthorizationServerMetadata,
        pre_authorized_code: String,
        tx_code_definition: TxCodeDefinition,
    ) -> Self {
        Self {
            client,
            credential_offer,
            authorization_server_metadata,
            pre_authorized_code,
            tx_code_definition,
        }
    }

    pub fn tx_code_definition(&self) -> &TxCodeDefinition {
        &self.tx_code_definition
    }

    /// Generates the Client Attestation PoP's and DPoP proof's `jti` by
    /// calling `jti` — at most once each, and only when needed. See
    /// [`Self::proceed`] for a version that generates them randomly.
    pub async fn proceed_with(
        self,
        http_client: &impl HttpClient,
        tx_code: String,
        jti: impl Fn() -> String + Send + Clone + 'static,
    ) -> Result<CredentialToken<C::Profile>, ClientError> {
        let token_endpoint = TokenEndpoint::new(
            &self.client,
            self.authorization_server_metadata
                .token_endpoint
                .as_deref()
                .ok_or(ClientError::MissingTokenEndpoint)?,
        );

        let response = token_endpoint
            .exchange_pre_authorized_code(self.pre_authorized_code, Some(tx_code))
            .with_client_attestation_with(&self.authorization_server_metadata, jti.clone())
            .with_dpop_with(None, None, jti)
            .send(http_client)
            .await
            .map_err(ClientError::authorization)?;

        Ok(CredentialToken {
            credential_offer: self.credential_offer,
            authorization_server_metadata: self.authorization_server_metadata,
            requested_scope: None,
            response,
        })
    }

    /// Generates the Client Attestation PoP's and DPoP proof's `jti`
    /// randomly (requires the `rand` feature). See [`Self::proceed_with`]
    /// for a version that doesn't need one.
    #[cfg(feature = "rand")]
    pub async fn proceed(
        self,
        http_client: &impl HttpClient,
        tx_code: String,
    ) -> Result<CredentialToken<C::Profile>, ClientError> {
        self.proceed_with(http_client, tx_code, crate::util::generate_jti)
            .await
    }
}
