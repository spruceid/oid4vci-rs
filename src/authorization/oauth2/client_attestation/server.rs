use std::borrow::Borrow;

use iref::UriBuf;
use open_auth2::{
    client::OAuth2ClientError,
    http::{self, Method, StatusCode},
    server::AuthorizationServerMetadata,
    transport::{expect_content_type, HttpClient, APPLICATION_JSON},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClientAttestationServerParams {
    /// Challenge endpoint.
    ///
    /// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#name-challenge-retrieval>
    pub challenge_endpoint: Option<UriBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationChallengeResponse {
    /// Challenge to be used in the OAuth-Attestation-PoP.
    pub attestation_challenge: String,
}

impl AttestationChallengeResponse {
    pub fn new(attestation_challenge: String) -> Self {
        Self {
            attestation_challenge,
        }
    }
}

pub trait ClientAttestationServerMetadata {
    #[allow(async_fn_in_trait)]
    async fn get_attestation_challenge(
        &self,
        http_client: &impl HttpClient,
    ) -> Result<Option<String>, OAuth2ClientError>;
}

impl<P> ClientAttestationServerMetadata for AuthorizationServerMetadata<P>
where
    P: Borrow<ClientAttestationServerParams>,
{
    #[allow(async_fn_in_trait)]
    async fn get_attestation_challenge(
        &self,
        http_client: &impl HttpClient,
    ) -> Result<Option<String>, OAuth2ClientError> {
        match attestation_challenge_request(self) {
            Some(request) => {
                let response = http_client.send(request).await?;
                attestation_challenge_response(response).map(|r| Some(r.attestation_challenge))
            }
            None => Ok(None),
        }
    }
}

fn attestation_challenge_request<P>(
    metadata: &AuthorizationServerMetadata<P>,
) -> Option<http::Request<Vec<u8>>>
where
    P: Borrow<ClientAttestationServerParams>,
{
    let url = metadata.extra.borrow().challenge_endpoint.as_deref()?;
    let mut request = http::Request::new(Vec::new());
    *request.method_mut() = Method::POST;
    *request.uri_mut() = url.as_str().parse().unwrap();
    Some(request)
}

fn attestation_challenge_response(
    response: http::Response<Vec<u8>>,
) -> Result<AttestationChallengeResponse, OAuth2ClientError> {
    let status = response.status();
    if status != StatusCode::OK {
        return Err(OAuth2ClientError::ServerError(status));
    }

    expect_content_type(response.headers(), &APPLICATION_JSON)?;
    serde_json::from_slice(response.body()).map_err(OAuth2ClientError::response)
}
