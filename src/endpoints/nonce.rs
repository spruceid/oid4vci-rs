use iref::Uri;
use open_auth2::{
    client::OAuth2ClientError,
    endpoints::HttpRequest,
    http,
    transport::{expect_content_type, HttpClient, NoContent, APPLICATION_JSON},
};
use serde::{Deserialize, Serialize};

pub struct NonceEndpoint<'a, C> {
    pub client: &'a C,
    pub uri: &'a Uri,
}

impl<'a, C> NonceEndpoint<'a, C> {
    pub fn new(client: &'a C, uri: &'a Uri) -> Self {
        Self { client, uri }
    }
}

impl<'a, C> Clone for NonceEndpoint<'a, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, C> Copy for NonceEndpoint<'a, C> {}

impl<'a, C> NonceEndpoint<'a, C> {
    pub fn get(self) -> NonceRequestBuilder<'a, C> {
        NonceRequestBuilder::new(self, NonceRequest)
    }
}

pub struct NonceRequestBuilder<'a, C, T = NonceRequest> {
    pub endpoint: NonceEndpoint<'a, C>,
    pub request: T,
}

impl<'a, C, T> NonceRequestBuilder<'a, C, T> {
    pub fn new(endpoint: NonceEndpoint<'a, C>, request: T) -> Self {
        Self { endpoint, request }
    }

    pub async fn send(self, http_client: &impl HttpClient) -> Result<T::Response, OAuth2ClientError>
    where
        T: HttpRequest<NonceEndpoint<'a, C>>,
    {
        self.request.send(&self.endpoint, http_client).await
    }
}

pub struct NonceRequest;

impl<'a, C> HttpRequest<NonceEndpoint<'a, C>> for NonceRequest {
    type ContentType = NoContent;
    type RequestBody<'b>
        = ()
    where
        Self: 'b;
    type Response = NonceResponse;
    type ResponsePayload = NonceResponse;

    async fn build_request(
        &self,
        endpoint: &NonceEndpoint<'a, C>,
        _http_client: &impl HttpClient,
    ) -> Result<http::Request<Self::RequestBody<'_>>, OAuth2ClientError> {
        Ok(http::Request::builder()
            .method(http::Method::POST)
            .uri(endpoint.uri.as_str())
            .body(())
            .unwrap())
    }

    fn decode_response(
        &self,
        _endpoint: &NonceEndpoint<'a, C>,
        response: http::Response<Vec<u8>>,
    ) -> Result<http::Response<Self::ResponsePayload>, OAuth2ClientError> {
        let status = response.status();
        if status != http::StatusCode::OK {
            return Err(OAuth2ClientError::ServerError(status));
        }

        expect_content_type(response.headers(), &APPLICATION_JSON)?;
        let body = serde_json::from_slice(response.body()).map_err(OAuth2ClientError::response)?;
        Ok(response.map(|_| body))
    }

    async fn process_response(
        &self,
        _endpoint: &NonceEndpoint<'a, C>,
        _http_client: &impl HttpClient,
        response: http::Response<Self::ResponsePayload>,
    ) -> Result<Self::Response, OAuth2ClientError> {
        Ok(response.into_body())
    }
}

/// Nonce Response.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-response>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    pub c_nonce: String,
}

/// Axum support.
#[cfg(feature = "axum")]
mod axum {
    use ::axum::{
        body::Body,
        http::{
            header::{CACHE_CONTROL, CONTENT_TYPE},
            StatusCode,
        },
        response::{IntoResponse, Response},
    };

    use super::*;

    impl IntoResponse for NonceResponse {
        fn into_response(self) -> Response {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, &APPLICATION_JSON)
                .header(CACHE_CONTROL, "no-store")
                .body(Body::from(
                    serde_json::to_vec(&self)
                        // UNWRAP SAFETY: Nonce Response is always serializable as JSON.
                        .unwrap(),
                ))
                .unwrap()
        }
    }
}
