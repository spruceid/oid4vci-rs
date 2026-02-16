use std::borrow::Borrow;

use open_auth2::{
    client::{OAuth2Client, OAuth2ClientError},
    endpoints::{Endpoint, HttpRequest, RedirectRequest, RequestBuilder},
    http,
    server::AuthorizationServerMetadata,
    transport::HttpClient,
};
use rand::{
    distr::{Alphanumeric, SampleString},
    rng,
};
use ssi::claims::{jws::JwsSigner, Jws, JwsBuf, JwsPayload, SignatureError};

use crate::authorization::oauth2::client_attestation::{
    ClientAttestationAndPopRef, ClientAttestationServerMetadata, ClientAttestationServerParams,
    HttpRequestWithOAuthClientAttestation,
};

use super::ClientAttestationPop;

pub trait AttestedOAuth2Client: OAuth2Client {
    type Signer: JwsSigner;

    /// Client Attestation delivered by the attester.
    fn attestation(&self) -> Option<&Jws>;

    /// Client Attestation PoP signer.
    fn attestation_pop_signer(&self) -> &Self::Signer;

    #[allow(async_fn_in_trait)]
    async fn generate_attestation_pop(
        &self,
        aud: String,
        challenge: Option<String>,
    ) -> Result<JwsBuf, SignatureError> {
        ClientAttestationPop::new(
            self.client_id().to_owned(),
            aud,
            Alphanumeric.sample_string(&mut rng(), 30),
            challenge,
        )
        .sign(self.attestation_pop_signer())
        .await
    }
}

pub struct WithClientAttestation<'a, M, T> {
    pub authorization_server_metadata: &'a AuthorizationServerMetadata<M>,
    pub value: T,
}

impl<'a, M, T> WithClientAttestation<'a, M, T> {
    pub fn new(
        value: T,
        authorization_server_metadata: &'a AuthorizationServerMetadata<M>,
    ) -> Self {
        Self {
            value,
            authorization_server_metadata,
        }
    }
}

impl<'a, M, T> std::ops::Deref for WithClientAttestation<'a, M, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<'a, M, T> std::borrow::Borrow<T> for WithClientAttestation<'a, M, T> {
    fn borrow(&self) -> &T {
        &self.value
    }
}

impl<'a, M, T> RedirectRequest for WithClientAttestation<'a, M, T>
where
    T: RedirectRequest,
{
    type RequestBody<'b>
        = T::RequestBody<'b>
    where
        Self: 'b;

    fn build_query(&self) -> Self::RequestBody<'_> {
        self.value.build_query()
    }
}

pub trait AddClientAttestation<'a, M> {
    type Output;

    fn with_client_attestation(
        self,
        authorization_server_metadata: &'a AuthorizationServerMetadata<M>,
    ) -> Self::Output;
}

impl<'a, E, M, T> AddClientAttestation<'a, M> for RequestBuilder<E, T>
where
    M: 'a,
{
    type Output = RequestBuilder<E, WithClientAttestation<'a, M, T>>;

    fn with_client_attestation(
        self,
        authorization_server_metadata: &'a AuthorizationServerMetadata<M>,
    ) -> Self::Output {
        self.map(|value| WithClientAttestation::new(value, authorization_server_metadata))
    }
}

impl<'a, M, T, E> HttpRequest<E> for WithClientAttestation<'a, M, T>
where
    M: Borrow<ClientAttestationServerParams>,
    E: Endpoint<Client: AttestedOAuth2Client>,
    T: HttpRequest<E>,
{
    type ContentType = T::ContentType;
    type RequestBody<'b>
        = T::RequestBody<'b>
    where
        Self: 'b;
    type ResponsePayload = T::ResponsePayload;
    type Response = T::Response;

    async fn build_request(
        &self,
        endpoint: &E,
        http_client: &impl HttpClient,
    ) -> Result<http::Request<Self::RequestBody<'_>>, OAuth2ClientError> {
        let mut request = self.value.build_request(endpoint, http_client).await?;

        if let Some(client_attestation) = endpoint.client().attestation() {
            let challenge = self
                .authorization_server_metadata
                .get_attestation_challenge(http_client)
                .await?;

            let pop = endpoint
                .client()
                .generate_attestation_pop(
                    self.authorization_server_metadata
                        .issuer
                        .as_str()
                        .to_owned(),
                    challenge,
                )
                .await
                .map_err(OAuth2ClientError::request)?;

            request.insert_oauth_client_attestation(ClientAttestationAndPopRef {
                client_attestation,
                client_attestation_pop: &pop,
            });
        }

        Ok(request)
    }

    fn decode_response(
        &self,
        endpoint: &E,
        response: http::Response<Vec<u8>>,
    ) -> Result<http::Response<Self::ResponsePayload>, OAuth2ClientError> {
        self.value.decode_response(endpoint, response)
    }

    async fn process_response(
        &self,
        endpoint: &E,
        http_client: &impl HttpClient,
        response: http::Response<Self::ResponsePayload>,
    ) -> Result<Self::Response, OAuth2ClientError> {
        self.value
            .process_response(endpoint, http_client, response)
            .await
    }
}
