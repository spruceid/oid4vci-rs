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

    /// Generates the DPoP proof's `jti`, called at most once per request
    /// attempt, and only if the client has a DPoP public JWK configured.
    jti: Box<dyn Fn() -> String + Send>,
}

impl<'a, T> WithDpop<'a, T> {
    /// Creates a new instance with a random `jti` generator (requires the
    /// `rand` feature). See [`Self::new_with`] for a version that doesn't
    /// need one.
    #[cfg(feature = "rand")]
    pub fn new(value: T, dpop: OAuth2DpopOptions<'a>) -> Self {
        Self::new_with(value, dpop, crate::util::generate_jti)
    }

    /// Creates a new instance, generating the DPoP proof's `jti` by calling
    /// `jti`.
    pub fn new_with(
        value: T,
        dpop: OAuth2DpopOptions<'a>,
        jti: impl Fn() -> String + Send + 'static,
    ) -> Self {
        Self {
            value,
            dpop,
            jti: Box::new(jti),
        }
    }

    /// Builds the inner request, attaching a DPoP proof if the client has
    /// a DPoP public JWK configured.
    ///
    /// `nonce` is taken separately, rather than read from `self.dpop.nonce`,
    /// so a retry can supply the nonce the server just handed back instead.
    async fn build_request<'b, E>(
        &'b self,
        endpoint: &E,
        http_client: &impl HttpClient,
        nonce: Option<&str>,
    ) -> Result<http::Request<T::RequestBody<'b>>, OAuth2ClientError>
    where
        E: Endpoint<Client: OAuth2DpopClient>,
        T: HttpRequest<E>,
    {
        let mut request = self.value.build_request(endpoint, http_client).await?;

        if let Some(public_jwk) = endpoint.client().dpop_public_jwk() {
            let htm = request.method().to_string();
            let mut htu = UriBuf::new(request.uri().to_string().into_bytes()).unwrap();
            htu.set_query(None);
            htu.set_fragment(None);

            let dpop = DpopProof::new_with(
                htm,
                htu,
                self.dpop.ath.clone(),
                nonce.map(ToOwned::to_owned),
                (self.jti)(),
            )
            .sign(DpopSigner::new(endpoint.client().dpop_signer(), public_jwk))
            .await
            .map_err(OAuth2ClientError::request)?;

            request.insert_dpop(dpop);
        }

        Ok(request)
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

    /// Wraps request building, generating the DPoP proof's `jti` by
    /// calling `jti` — at most once per request attempt, and only when
    /// needed.
    fn with_dpop_with(
        self,
        ath: Option<&AccessToken>,
        nonce: Option<&'a str>,
        jti: impl Fn() -> String + Send + 'static,
    ) -> Self::Output;

    /// Wraps request building, generating the DPoP proof's `jti` randomly
    /// (requires the `rand` feature). See [`Self::with_dpop_with`] for a
    /// version that doesn't need one.
    #[cfg(feature = "rand")]
    fn with_dpop(self, ath: Option<&AccessToken>, nonce: Option<&'a str>) -> Self::Output
    where
        Self: Sized,
    {
        self.with_dpop_with(ath, nonce, crate::util::generate_jti)
    }
}

impl<'a, E, T> AddDpop<'a> for RequestBuilder<E, T> {
    type Output = RequestBuilder<E, WithDpop<'a, T>>;

    fn with_dpop_with(
        self,
        ath: Option<&AccessToken>,
        nonce: Option<&'a str>,
        jti: impl Fn() -> String + Send + 'static,
    ) -> Self::Output {
        self.map(|value| WithDpop::new_with(value, OAuth2DpopOptions::new(ath, nonce), jti))
    }
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
        self.build_request(endpoint, http_client, self.dpop.nonce)
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
                let mut request = self
                    .build_request(endpoint, http_client, Some(nonce))
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
