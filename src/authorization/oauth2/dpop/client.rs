use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use iref::UriBuf;
use open_auth2::{
    client::{OAuth2Client, OAuth2ClientError},
    endpoints::{Endpoint, HttpRequest, RedirectRequest, RequestBuilder},
    http::{self, header},
    transport::{ContentType, HttpClient},
    AccessToken,
};
use ssi::{claims::jws::JwsSigner, crypto::hashes::sha256::sha256, JWK};

use crate::authorization::oauth2::dpop::{
    server::DpopResponse, DpopErrorResponse, DpopSigner, DPOP_NONCE,
};

use super::{DpopProof, DpopRequest};

pub trait OAuth2DpopClient: OAuth2Client {
    type Signer: JwsSigner;

    fn dpop_signer(&self) -> &Self::Signer;

    fn dpop_public_jwk(&self) -> Option<&JWK>;
}

pub struct OAuth2DpopOptions<'a> {
    pub ath: Option<String>,
    pub nonce: Option<&'a str>,
}

impl<'a> OAuth2DpopOptions<'a> {
    pub fn new(token: Option<&AccessToken>, nonce: Option<&'a str>) -> Self {
        let ath = token.map(|token| BASE64_URL_SAFE_NO_PAD.encode(sha256(token.as_bytes())));
        Self { ath, nonce }
    }
}

pub struct WithDpop<'a, T> {
    pub dpop: OAuth2DpopOptions<'a>,
    pub value: T,
}

impl<'a, T> WithDpop<'a, T> {
    pub fn new(value: T, dpop: OAuth2DpopOptions<'a>) -> Self {
        Self { value, dpop }
    }
}

impl<'a, T> std::ops::Deref for WithDpop<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<'a, T> std::borrow::Borrow<T> for WithDpop<'a, T> {
    fn borrow(&self) -> &T {
        &self.value
    }
}

impl<'a, T: RedirectRequest> RedirectRequest for WithDpop<'a, T> {
    type RequestBody<'b>
        = T::RequestBody<'b>
    where
        Self: 'b;

    fn build_query(&self) -> T::RequestBody<'_> {
        self.value.build_query()
    }
}

pub trait AddDpop<'a> {
    type Output;

    fn with_dpop(self, ath: Option<&AccessToken>, nonce: Option<&'a str>) -> Self::Output;
}

impl<'a, E, T> AddDpop<'a> for RequestBuilder<E, T> {
    type Output = RequestBuilder<E, WithDpop<'a, T>>;

    fn with_dpop(self, ath: Option<&AccessToken>, nonce: Option<&'a str>) -> Self::Output {
        self.map(|value| WithDpop::new(value, OAuth2DpopOptions::new(ath, nonce)))
    }
}

async fn build_request<'b, E, T>(
    endpoint: &E,
    http_client: &impl HttpClient,
    value: &'b T,
    ath: Option<&str>,
    nonce: Option<&str>,
) -> Result<http::Request<T::RequestBody<'b>>, OAuth2ClientError>
where
    E: Endpoint<Client: OAuth2DpopClient>,
    T: HttpRequest<E>,
{
    let mut request = value.build_request(endpoint, http_client).await?;

    if let Some(public_jwk) = endpoint.client().dpop_public_jwk() {
        let htm = request.method().to_string();
        let mut htu = UriBuf::new(request.uri().to_string().into_bytes()).unwrap();
        htu.set_query(None);
        htu.set_fragment(None);

        let dpop = DpopProof::new(
            htm,
            htu,
            ath.map(ToOwned::to_owned),
            nonce.map(ToOwned::to_owned),
        )
        .sign(DpopSigner::new(endpoint.client().dpop_signer(), public_jwk))
        .await
        .map_err(OAuth2ClientError::request)?;

        request.insert_dpop(dpop);
    }

    Ok(request)
}

impl<'a, E, T> HttpRequest<E> for WithDpop<'a, T>
where
    E: Endpoint<Client: OAuth2DpopClient>,
    T: HttpRequest<E>,
{
    type ContentType = T::ContentType;
    type RequestBody<'b>
        = T::RequestBody<'b>
    where
        Self: 'b;
    type ResponsePayload = DpopResponse<T::ResponsePayload>;
    type Response = T::Response;

    async fn build_request(
        &self,
        endpoint: &E,
        http_client: &impl HttpClient,
    ) -> Result<http::Request<Self::RequestBody<'_>>, OAuth2ClientError> {
        build_request(
            endpoint,
            http_client,
            &self.value,
            self.dpop.ath.as_deref(),
            self.dpop.nonce,
        )
        .await
    }

    fn decode_response(
        &self,
        client: &E,
        response: http::Response<Vec<u8>>,
    ) -> Result<http::Response<Self::ResponsePayload>, OAuth2ClientError> {
        match response.status() {
            http::StatusCode::UNAUTHORIZED => Ok(response.map(|_| {
                DpopResponse::RequireDpop(DpopErrorResponse {
                    error_description: None,
                })
            })),
            http::StatusCode::BAD_REQUEST => {
                if let Ok(r) = serde_json::from_slice::<DpopErrorResponse>(response.body()) {
                    Ok(response.map(|_| DpopResponse::RequireDpop(r)))
                } else {
                    Ok(self
                        .value
                        .decode_response(client, response)?
                        .map(DpopResponse::Ok))
                }
            }
            _ => Ok(self
                .value
                .decode_response(client, response)?
                .map(DpopResponse::Ok)),
        }
    }

    async fn process_response(
        &self,
        endpoint: &E,
        http_client: &impl HttpClient,
        response: http::Response<Self::ResponsePayload>,
    ) -> Result<Self::Response, open_auth2::client::OAuth2ClientError> {
        let (parts, body) = response.into_parts();

        match body {
            DpopResponse::RequireDpop(_) => {
                log::debug!("server requires DPoP nonce");
                if endpoint.client().dpop_public_jwk().is_none() {
                    return Err(OAuth2ClientError::response(
                        "server requires a `DPoP` header, but no client public JWK is set",
                    ));
                }

                let mut nonces = parts.headers.get_all(DPOP_NONCE).iter();

                let Some(nonce) = nonces.next() else {
                    return Err(OAuth2ClientError::response("missing `DPoP-Nonce` header"));
                };

                if nonces.next().is_some() {
                    return Err(OAuth2ClientError::response("too many `DPoP-Nonce` headers"));
                }

                let nonce = nonce.to_str().map_err(OAuth2ClientError::response)?;

                // Try again, with a nonce.
                log::debug!("trying again with a nonce");
                let mut request = build_request(
                    endpoint,
                    http_client,
                    &self.value,
                    self.dpop.ath.as_deref(),
                    Some(nonce),
                )
                .await?;

                if let Some(content_type) = Self::ContentType::VALUE {
                    request
                        .headers_mut()
                        .insert(header::CONTENT_TYPE, content_type);
                }

                let encoded_request = request.map(|body| Self::ContentType::encode(&body));

                log::debug!("sending request again");
                let response = http_client.send(encoded_request).await?;

                let parsed_response = self.value.decode_response(endpoint, response)?;
                self.value
                    .process_response(endpoint, http_client, parsed_response)
                    .await
            }
            DpopResponse::Ok(body) => {
                self.value
                    .process_response(
                        endpoint,
                        http_client,
                        http::Response::from_parts(parts, body),
                    )
                    .await
            }
        }
    }
}
