use core::fmt;
use std::{borrow::Cow, time::Duration};

use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use iref::UriBuf;
use oid4vci::{
    authorization::server::{Oid4VciAuthorizationServerParams, Oid4vciAuthorizationServerMetadata},
    client::Oid4vciTokenParams,
};
use open_auth2::{
    endpoints::{
        pushed_authorization::{PushedAuthorizationRequest, PushedAuthorizationResponse},
        token::TokenResponse,
    },
    grant::{
        authorization_code::{
            AuthorizationCodeAuthorizationRequest, AuthorizationCodeTokenRequest,
        },
        pre_authorized_code::PreAuthorizedCodeTokenRequest,
    },
    server::{OAuth2ParServer, OAuth2Server, OAuth2ServerError},
    AccessToken, AccessTokenBuf, ClientIdBuf, CodeBuf, Stateful,
};
use rand::{
    distr::{Alphanumeric, SampleString},
    rng,
};
use serde::{Deserialize, Serialize};
use time::UtcDateTime;

use crate::{Error, Server};

#[derive(Default)]
pub struct OAuth2State {
    pre_authorized_codes: DashMap<String, PreAuthorizedCodeMetadata>,

    par: DashMap<UriBuf, PushedAuthorization>,

    authorization_code: DashMap<CodeBuf, AuthorizationCodeMetadata>,

    access_tokens: DashMap<AccessTokenBuf, AccessTokenMetadata>,
}

impl OAuth2State {
    pub fn new_pre_authorized_code(&self, m: PreAuthorizedCodeMetadata) -> String {
        let code = rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 30);
        self.pre_authorized_codes.insert(code.clone(), m);
        code
    }

    pub fn access_token_metadata(
        &self,
        access_token: &AccessToken,
    ) -> Option<dashmap::mapref::one::Ref<'_, AccessTokenBuf, AccessTokenMetadata>> {
        self.access_tokens.get(access_token)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum AuthorizationRequest {
    Pushed(PushedAuthorizationRequest),
    Direct(AuthorizationCodeAuthorizationRequest),
}

impl Server {
    async fn authorize_direct(
        &self,
        Stateful {
            state,
            value: request,
        }: Stateful<AuthorizationCodeAuthorizationRequest>,
    ) -> Result<Redirect, Error> {
        match request.redirect_url(None).map(ToOwned::to_owned) {
            Some(redirect_uri) => {
                let client_id = request.client_id.clone();
                let code = CodeBuf::new(Alphanumeric.sample_string(&mut rng(), 30)).unwrap();
                let full_redirect_uri = request.grant(state, code.clone(), None).unwrap();

                let m = AuthorizationCodeMetadata {
                    client_id,
                    redirect_uri,
                };

                self.oauth2.authorization_code.insert(code, m);

                Ok(Redirect(full_redirect_uri))
            }
            None => Err(Error::MissingRedirectUrl),
        }
    }
}

impl OAuth2Server for Server {
    type Metadata = Oid4VciAuthorizationServerParams;
    type AuthorizationRequest = AuthorizationRequest;
    type TokenRequest = TokenRequest;
    type TokenResponse = TokenResponse<TokenType, Oid4vciTokenParams>;

    async fn metadata(
        &self,
    ) -> Result<Cow<'_, Oid4vciAuthorizationServerMetadata>, OAuth2ServerError> {
        Ok(match &self.config.authorization_server_metadata {
            Some(metadata) => Cow::Borrowed(metadata),
            None => Cow::Owned(self.config.default_authorization_server_metadata()),
        })
    }

    async fn authorize(
        &self,
        Stateful {
            state,
            value: request,
        }: Stateful<AuthorizationRequest>,
    ) -> impl IntoResponse {
        match request {
            AuthorizationRequest::Direct(request) => {
                self.authorize_direct(Stateful {
                    state,
                    value: request,
                })
                .await
            }
            AuthorizationRequest::Pushed(request) => {
                match self.oauth2.par.remove(&request.request_uri) {
                    Some((_, pa)) => {
                        if pa.expires_at < UtcDateTime::now() {
                            return Err(Error::Expired);
                        }

                        if *pa.request.client_id != request.client_id {
                            return Err(Error::Unauthorized);
                        }

                        self.authorize_direct(pa.request).await
                    }
                    None => Err(Error::UnknownRequestUrl),
                }
            }
        }
    }

    async fn token(
        &self,
        token_request: Self::TokenRequest,
    ) -> Result<Self::TokenResponse, OAuth2ServerError> {
        log::debug!("token request: {token_request:#?}");

        let m = match token_request {
            TokenRequest::PreAuthorizedCode(request) => {
                let m = self
                    .oauth2
                    .pre_authorized_codes
                    .get(&request.pre_authorized_code)
                    .ok_or(OAuth2ServerError::UnauthorizedClient)?;

                if let Some(expected_tx_code) = &m.tx_code {
                    let tx_code = request
                        .tx_code
                        .ok_or(OAuth2ServerError::UnauthorizedClient)?;

                    if tx_code != *expected_tx_code {
                        return Err(OAuth2ServerError::UnauthorizedClient);
                    }
                }

                AccessTokenMetadata {
                    client_id: request.client_id,
                }
            }
            TokenRequest::AuthorizationCode(request) => {
                let m = self
                    .oauth2
                    .authorization_code
                    .get(&request.code)
                    .ok_or(OAuth2ServerError::UnauthorizedClient)?;

                if !m.check_request(&request) {
                    return Err(OAuth2ServerError::UnauthorizedClient);
                }

                AccessTokenMetadata {
                    client_id: request.client_id,
                }
            }
        };

        let access_token = AccessTokenBuf::new(Alphanumeric.sample_string(&mut rng(), 30)).unwrap();
        self.oauth2.access_tokens.insert(access_token.to_owned(), m);

        Ok(TokenResponse::new(
            access_token,
            TokenType::Bearer,
            Oid4vciTokenParams {
                authorization_details: self.config.authorization_details().into(),
            },
        ))
    }
}

impl OAuth2ParServer for Server {
    type PushedAuthorizationRequest = AuthorizationCodeAuthorizationRequest;

    async fn par(
        &self,
        request: Stateful<Self::PushedAuthorizationRequest>,
    ) -> Result<PushedAuthorizationResponse, OAuth2ServerError> {
        log::info!("push request: {request:#?}");

        let request_uri = UriBuf::new(
            format!(
                "urn:ietf:params:oauth:request_uri:{}",
                Alphanumeric.sample_string(&mut rng(), 30)
            )
            .into_bytes(),
        )
        .unwrap();
        let expires_in = 1000;
        let expires_at = UtcDateTime::now() + Duration::from_secs(expires_in);

        self.oauth2.par.insert(
            request_uri.clone(),
            PushedAuthorization {
                request,
                expires_at,
            },
        );

        Ok(PushedAuthorizationResponse {
            request_uri,
            expires_in,
        })
    }
}

pub struct PreAuthorizedCodeMetadata {
    pub tx_code: Option<String>,
}

pub struct AuthorizationCodeMetadata {
    client_id: ClientIdBuf,
    redirect_uri: UriBuf,
}

pub struct PushedAuthorization {
    request: Stateful<AuthorizationCodeAuthorizationRequest>,
    expires_at: UtcDateTime,
}

impl AuthorizationCodeMetadata {
    fn check_request(&self, request: &AuthorizationCodeTokenRequest) -> bool {
        request.client_id.as_ref() == Some(&self.client_id)
            && request.redirect_uri.as_ref() == Some(&self.redirect_uri)
    }
}

pub struct AccessTokenMetadata {
    pub client_id: Option<ClientIdBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TokenRequest {
    AuthorizationCode(AuthorizationCodeTokenRequest),
    PreAuthorizedCode(PreAuthorizedCodeTokenRequest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum TokenType {
    Bearer,
}

impl TokenType {
    fn as_str(&self) -> &'static str {
        "Bearer"
    }
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl open_auth2::endpoints::token::TokenType for TokenType {}

struct Redirect(UriBuf);

impl IntoResponse for Redirect {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", self.0.to_string())
            .body(Body::empty())
            .unwrap()
    }
}
