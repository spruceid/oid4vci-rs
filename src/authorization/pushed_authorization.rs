//! [RFC 9126]: OAuth 2.0 Pushed Authorization Requests.
//!
//! [RFC 9126]: <https://www.rfc-editor.org/rfc/rfc9126.html>
use std::borrow::Cow;

use crate::{
    authorization::{
        authorization_details::{
            CredentialAuthorizationDetailsRequest, CredentialAuthorizationParams,
        },
        request::Oid4vciAuthorizationRequest,
    },
    util::http::{check_content_type, HttpError, MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON},
};
use iref::{Uri, UriBuf};
use oauth2::{
    http::{
        self,
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    url::Url,
    AsyncHttpClient, AuthUrl, AuthorizationRequest, ClientId, CsrfToken, EndpointSet,
    EndpointState, ErrorResponse, HttpRequest, PkceCodeChallenge, RevocableToken, Scope,
    SyncHttpClient, TokenIntrospectionResponse, TokenResponse,
};
use serde::{Deserialize, Serialize};

pub trait OAuth2PushAuthorizationClient {
    fn push_authorize_url<'a>(
        &'a self,
        par_endpoint_url: &'a Uri,
        state_fn: impl FnOnce() -> CsrfToken,
    ) -> PushedAuthorizationRequest<'a>;
}

impl<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
        HasTokenUrl,
    > OAuth2PushAuthorizationClient
    for oauth2::Client<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        EndpointSet,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
        HasTokenUrl,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
    HasTokenUrl: EndpointState,
{
    fn push_authorize_url<'a>(
        &'a self,
        par_endpoint_url: &'a Uri,
        state_fn: impl FnOnce() -> CsrfToken,
    ) -> PushedAuthorizationRequest<'a> {
        PushedAuthorizationRequest {
            inner: self.authorize_url(state_fn),
            client_id: self.client_id(),
            par_auth_url: par_endpoint_url,
            auth_url: self.auth_uri(),
        }
    }
}

/// Pushed Authorization Request.
pub struct PushedAuthorizationRequest<'a> {
    inner: AuthorizationRequest<'a>,
    client_id: &'a ClientId,
    par_auth_url: &'a Uri,
    auth_url: &'a AuthUrl,
}

impl<'a> PushedAuthorizationRequest<'a> {
    pub fn request<C>(self, http_client: &C) -> Result<(Url, CsrfToken), HttpError>
    where
        C: SyncHttpClient,
    {
        let client_id = self.client_id;
        let par_auth_url = self.par_auth_url;
        let auth_url = self.auth_url;

        let (http_request, token) = self.prepare_request();

        let http_response = http_client
            .call(http_request)
            .map_err(HttpError::query(par_auth_url))?;

        let parsed_response = Self::parse_response(par_auth_url, http_response)?;

        let mut result = auth_url.url().clone();

        result
            .query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("request_uri", parsed_response.request_uri.as_str());

        Ok((result, token))
    }

    pub async fn request_async<'c, C>(
        self,
        http_client: &'c C,
    ) -> Result<(Url, CsrfToken), HttpError>
    where
        C: AsyncHttpClient<'c>,
    {
        let client_id = self.client_id;
        let par_auth_url = self.par_auth_url;
        let auth_url = self.auth_url;

        let (http_request, token) = self.prepare_request();

        let http_response = http_client
            .call(http_request)
            .await
            .map_err(HttpError::query(par_auth_url))?;

        let parsed_response = Self::parse_response(par_auth_url, http_response)?;

        let mut result = auth_url.url().clone();

        result
            .query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("request_uri", parsed_response.request_uri.as_str());

        Ok((result, token))
    }

    fn prepare_request(self) -> (HttpRequest, CsrfToken) {
        let (url, token) = self.inner.url();

        let query = url.query().unwrap_or_default();

        let request = http::Request::builder()
            .uri(self.par_auth_url.to_string())
            .method(Method::POST)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static(MIME_TYPE_FORM_URLENCODED),
            )
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .body(query.to_owned().into_bytes())
            // UNWRAP SAFETY: Parameters are type safe.
            .unwrap();

        (request, token)
    }

    fn parse_response(
        uri: &Uri,
        http_response: http::Response<Vec<u8>>,
    ) -> Result<PushedAuthorizationResponse, HttpError> {
        let status = http_response.status();
        if status != StatusCode::OK {
            return Err(HttpError::ServerError(uri.to_owned(), status));
        }

        check_content_type(uri, http_response.headers(), MIME_TYPE_JSON)?;
        serde_json::from_slice(http_response.body()).map_err(HttpError::json(uri))
    }

    /// Appends a collection of scopes to the token request.
    pub fn add_scopes<I>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = Scope>,
    {
        self.inner = self.inner.add_scopes(scopes);
        self
    }

    pub fn set_authorization_details<T: CredentialAuthorizationParams>(
        mut self,
        authorization_details: Vec<CredentialAuthorizationDetailsRequest<T>>,
    ) -> Self {
        self.inner = self.inner.set_authorization_details(authorization_details);
        self
    }

    pub fn set_issuer_state(mut self, issuer_state: &'a str) -> Self {
        self.inner = self.inner.set_issuer_state(issuer_state);
        self
    }

    pub fn set_issuer_state_option(mut self, issuer_state: Option<&'a str>) -> Self {
        self.inner = self.inner.set_issuer_state_option(issuer_state);
        self
    }

    pub fn set_client_assertion(self, client_assertion: String) -> Self {
        self.add_extra_param("client_assertion", client_assertion)
    }

    pub fn set_client_assertion_type(self, client_assertion_type: String) -> Self {
        self.add_extra_param("client_assertion_type", client_assertion_type)
    }

    pub fn set_pkce_challenge(mut self, pkce_code_challenge: PkceCodeChallenge) -> Self {
        self.inner = self.inner.set_pkce_challenge(pkce_code_challenge);
        self
    }

    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.add_extra_param(name, value);
        self
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PushedAuthorizationResponse {
    pub request_uri: UriBuf,
    pub expires_in: u64,
}

mod axum {
    use ::axum::{
        body::Body,
        response::{IntoResponse, Response},
    };

    use super::*;

    impl IntoResponse for PushedAuthorizationResponse {
        fn into_response(self) -> Response {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, MIME_TYPE_JSON)
                .body(Body::from(serde_json::to_vec(&self).unwrap()))
                .unwrap()
        }
    }
}
