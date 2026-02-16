use open_auth2::{
    client::OAuth2ClientError,
    endpoints::{HttpRequest, RedirectRequest, RequestBuilder},
    http,
    transport::HttpClient,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct WithIssuerState<'a, T> {
    pub issuer_state: Option<&'a str>,

    #[serde(flatten)]
    pub value: T,
}

impl<'a, T> WithIssuerState<'a, T> {
    pub fn new(value: T, issuer_state: Option<&'a str>) -> Self {
        Self {
            value,
            issuer_state,
        }
    }
}

impl<'a, T> std::ops::Deref for WithIssuerState<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<'a, T> std::borrow::Borrow<T> for WithIssuerState<'a, T> {
    fn borrow(&self) -> &T {
        &self.value
    }
}

impl<'a, T> RedirectRequest for WithIssuerState<'a, T>
where
    T: RedirectRequest,
{
    type RequestBody<'b>
        = WithIssuerState<'a, T::RequestBody<'b>>
    where
        Self: 'b;

    fn build_query(&self) -> Self::RequestBody<'_> {
        WithIssuerState::new(self.value.build_query(), self.issuer_state)
    }
}

impl<'a, E, T> HttpRequest<E> for WithIssuerState<'a, T>
where
    T: HttpRequest<E>,
{
    type ContentType = T::ContentType;
    type RequestBody<'b>
        = WithIssuerState<'a, T::RequestBody<'b>>
    where
        Self: 'b;
    type Response = T::Response;
    type ResponsePayload = T::ResponsePayload;

    async fn build_request(
        &self,
        endpoint: &E,
        http_client: &impl HttpClient,
    ) -> Result<http::Request<Self::RequestBody<'_>>, OAuth2ClientError> {
        self.value
            .build_request(endpoint, http_client)
            .await
            .map(|request| request.map(|value| WithIssuerState::new(value, self.issuer_state)))
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

pub trait AddIssuerState<'a> {
    type Output;

    fn with_issuer_state(self, state: Option<&'a str>) -> Self::Output;
}

impl<'a, E, T> AddIssuerState<'a> for RequestBuilder<E, T> {
    type Output = RequestBuilder<E, WithIssuerState<'a, T>>;

    fn with_issuer_state(self, state: Option<&'a str>) -> Self::Output {
        self.map(|value| WithIssuerState::new(value, state))
    }
}
