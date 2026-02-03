use std::{borrow::Cow, future::Future, sync::Arc};

use axum::{
    body::Body,
    extract::{Query, State},
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Form,
};
use iref::UriBuf;
use oauth2::{
    basic::{BasicErrorResponse, BasicErrorResponseType},
    url::Url,
    AuthorizationCode, ClientId, ExtraTokenFields, PkceCodeChallenge, RedirectUrl, Scope,
    StandardTokenResponse, TokenType,
};
use serde::{de::DeserializeOwned, Deserialize};

use crate::{
    authorization::{
        pushed_authorization::PushedAuthorizationResponse, request::AuthorizationRequestParams,
        response::AuthorizationErrorResponse, Stateful,
    },
    util::http::MIME_TYPE_JSON,
};

use super::AuthorizationServerMetadata;

pub enum OAuth2ServerError {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    ServerError(anyhow::Error),
}

impl OAuth2ServerError {
    pub fn server(e: impl Into<anyhow::Error>) -> Self {
        Self::ServerError(e.into())
    }
}

impl IntoResponse for OAuth2ServerError {
    fn into_response(self) -> Response {
        let error = match self {
            Self::InvalidRequest => BasicErrorResponseType::InvalidRequest,
            Self::InvalidClient => BasicErrorResponseType::InvalidClient,
            Self::InvalidGrant => BasicErrorResponseType::InvalidGrant,
            Self::UnauthorizedClient => BasicErrorResponseType::UnauthorizedClient,
            Self::UnsupportedGrantType => BasicErrorResponseType::UnsupportedGrantType,
            Self::InvalidScope => BasicErrorResponseType::InvalidScope,
            Self::ServerError(_) => {
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap()
            }
        };

        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(CONTENT_TYPE, MIME_TYPE_JSON)
            .body(Body::from(
                serde_json::to_vec(&BasicErrorResponse::new(error, None, None)).unwrap(),
            ))
            .unwrap()
    }
}

pub trait OAuth2Server: Sized + Send + Sync + 'static {
    type AuthParams: Sized + Send + Sync + DeserializeOwned + 'static;
    type TokenRequest: 'static + Send + Sync + DeserializeOwned;
    type TokenType: TokenType;
    type TokenParams: ExtraTokenFields;

    fn metadata(
        &self,
    ) -> impl Send + Future<Output = Result<Cow<'_, AuthorizationServerMetadata>, OAuth2ServerError>>;

    fn authorize(
        &self,
        request: ServerAuthorizationRequest<Self::AuthParams>,
    ) -> impl Send + Future<Output = impl IntoResponse>;

    fn token(
        &self,
        token_request: Self::TokenRequest,
    ) -> impl Send
           + Future<
        Output = Result<
            StandardTokenResponse<Self::TokenParams, Self::TokenType>,
            OAuth2ServerError,
        >,
    >;
}

pub trait OAuth2Router<S> {
    fn oauth2_routes(self) -> Self;
}

impl<S: OAuth2Server> OAuth2Router<S> for axum::Router<Arc<S>> {
    fn oauth2_routes(self) -> Self {
        self.route(
            "/.well-known/oauth-authorization-server",
            get(metadata::<S>),
        )
        .route("/authorize", get(authorize::<S>))
        .route("/token", post(token::<S>))
    }
}

/// Credential Issuer Metadata Endpoint.
async fn metadata<S>(State(server): State<Arc<S>>) -> impl IntoResponse
where
    S: OAuth2Server,
{
    // TODO support `Accept-Language` header.
    server
        .metadata()
        .await
        .map(|metadata| metadata.as_ref().into_response())
}

/// Authorization Request endpoint.
async fn authorize<S>(
    State(server): State<Arc<S>>,
    Query(Stateful {
        value: params,
        state,
    }): Query<Stateful<AuthorizationRequestParams<S::AuthParams>>>,
) -> Response
where
    S: OAuth2Server,
{
    server
        .authorize(ServerAuthorizationRequest { state, params })
        .await
        .into_response()
}

pub struct ServerAuthorizationRequest<P> {
    params: AuthorizationRequestParams<P>,
    state: Option<String>,
}

impl<P> ServerAuthorizationRequest<P> {
    pub fn client_id(&self) -> &ClientId {
        &self.params.client_id
    }

    pub fn pkce_challenge(&self) -> Option<&PkceCodeChallenge> {
        self.params.pkce_challenge.as_ref()
    }

    pub fn response_type(&self) -> &str {
        &self.params.response_type
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.params.scopes
    }

    pub fn params(&self) -> &P {
        &self.params.extra_params
    }

    pub fn redirect_url<'a>(
        &'a self,
        default_uri: Option<&'a RedirectUrl>,
    ) -> Option<&'a RedirectUrl> {
        self.params.redirect_uri.as_ref().or(default_uri)
    }

    pub fn grant(self, code: AuthorizationCode, default_uri: Option<&RedirectUrl>) -> Option<Url> {
        let mut url = self.redirect_url(default_uri)?.url().clone();

        {
            let mut query = url.query_pairs_mut();
            query.append_pair("code", code.secret());
            if let Some(state) = self.state {
                query.append_pair("state", &state);
            }
        }

        Some(url)
    }

    pub fn deny(
        self,
        error: AuthorizationErrorResponse,
        redirect_uri: Option<&RedirectUrl>,
    ) -> Option<Url> {
        let mut url = self
            .params
            .redirect_uri
            .as_ref()
            .or(redirect_uri)?
            .url()
            .clone();

        {
            let mut query = url.query_pairs_mut();
            query.append_pair("error", error.error().as_str());

            if let Some(value) = error.error_description() {
                query.append_pair("error_description", value);
            }

            if let Some(value) = error.error_uri() {
                query.append_pair("error_uri", value);
            }

            if let Some(state) = self.state {
                query.append_pair("state", &state);
            }
        }

        Some(url)
    }
}

/// Token Request endpoint.
async fn token<S>(
    State(server): State<Arc<S>>,
    Form(token_request): Form<S::TokenRequest>,
) -> impl IntoResponse
where
    S: OAuth2Server,
{
    server.token(token_request).await.map(|response| {
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, MIME_TYPE_JSON)
            .body(Body::from(serde_json::to_vec(&response).unwrap()))
            .unwrap()
    })
}

pub trait OAuth2ParServer: OAuth2Server {
    fn par(
        &self,
        request: ServerAuthorizationRequest<Self::AuthParams>,
    ) -> impl Send + Future<Output = Result<PushedAuthorizationResponse, OAuth2ServerError>>;

    fn par_authorize(
        &self,
        client_id: ClientId,
        request_uri: UriBuf,
    ) -> impl Send + Future<Output = impl IntoResponse>;
}

pub trait OAuth2ParRouter<S> {
    fn oauth2_par_routes(self) -> Self;
}

impl<S: OAuth2ParServer> OAuth2ParRouter<S> for axum::Router<Arc<S>> {
    fn oauth2_par_routes(self) -> Self {
        self.route(
            "/.well-known/oauth-authorization-server",
            get(metadata::<S>),
        )
        .route("/par", post(par::<S>))
        .route("/authorize", get(par_authorize::<S>))
        .route("/token", post(token::<S>))
    }
}

async fn par<S>(
    State(server): State<Arc<S>>,
    Form(Stateful {
        value: params,
        state,
    }): Form<Stateful<AuthorizationRequestParams<S::AuthParams>>>,
) -> impl IntoResponse
where
    S: OAuth2ParServer,
{
    server
        .par(ServerAuthorizationRequest { state, params })
        .await
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MaybePushedAuthorizationRequestParams<P> {
    NotPushed(Box<Stateful<AuthorizationRequestParams<P>>>),
    Pushed {
        client_id: ClientId,
        request_uri: UriBuf,
    },
}

/// Authorization Request endpoint, with support for Pushed Authorization
/// Requests.
async fn par_authorize<S>(
    State(server): State<Arc<S>>,
    Query(request): Query<MaybePushedAuthorizationRequestParams<S::AuthParams>>,
) -> impl IntoResponse
where
    S: OAuth2ParServer,
{
    match request {
        MaybePushedAuthorizationRequestParams::NotPushed(request) => {
            authorize(State(server), Query(*request))
                .await
                .into_response()
        }
        MaybePushedAuthorizationRequestParams::Pushed {
            client_id,
            request_uri,
        } => server
            .par_authorize(client_id, request_uri)
            .await
            .into_response(),
    }
}
