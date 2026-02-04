use std::{borrow::Cow, time::Duration};

use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use iref::UriBuf;
use oauth2::{
    url::Url, AccessToken, AuthorizationCode, ClientId, RedirectUrl, StandardTokenResponse,
};
use oid4vci::authorization::{
    pushed_authorization::PushedAuthorizationResponse,
    request::CredentialAuthorizationRequestParams,
    server::{
        AuthorizationServerMetadata, OAuth2ParServer, OAuth2Server, OAuth2ServerError,
        ServerAuthorizationRequest,
    },
    token::{
        AuthorizationCodeTokenRequest, CredentialTokenParams, PreAuthorizedCodeTokenRequest,
        RefreshTokenRequest,
    },
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

    authorization_code: DashMap<AuthorizationCode, AuthorizationCodeMetadata>,

    access_tokens: DashMap<AccessToken, AccessTokenMetadata>,
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
    ) -> Option<dashmap::mapref::one::Ref<'_, AccessToken, AccessTokenMetadata>> {
        self.access_tokens.get(access_token)
    }
}

impl OAuth2Server for Server {
    type AuthParams = CredentialAuthorizationRequestParams;
    type TokenRequest = TokenRequest;
    type TokenType = TokenType;
    type TokenParams = CredentialTokenParams;

    async fn metadata(&self) -> Result<Cow<'_, AuthorizationServerMetadata>, OAuth2ServerError> {
        Ok(match &self.config.authorization_server_metadata {
            Some(metadata) => Cow::Borrowed(metadata),
            None => Cow::Owned(self.config.default_authorization_server_metadata()),
        })
    }

    async fn authorize(
        &self,
        request: ServerAuthorizationRequest<Self::AuthParams>,
    ) -> impl IntoResponse {
        match request.redirect_url(None).cloned() {
            Some(redirect_uri) => {
                let client_id = request.client_id().clone();
                let code = AuthorizationCode::new(Alphanumeric.sample_string(&mut rng(), 30));
                let full_redirect_uri = request.grant(code.clone(), None).unwrap();

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

    async fn token(
        &self,
        token_request: Self::TokenRequest,
    ) -> Result<StandardTokenResponse<Self::TokenParams, Self::TokenType>, OAuth2ServerError> {
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
                    client_id: Some(request.client_id),
                }
            }
            _ => return Err(OAuth2ServerError::InvalidGrant),
        };

        let access_token = AccessToken::new(Alphanumeric.sample_string(&mut rng(), 30));
        self.oauth2.access_tokens.insert(access_token.clone(), m);

        Ok(StandardTokenResponse::new(
            access_token,
            TokenType::Bearer,
            CredentialTokenParams {
                authorization_details: self.config.authorization_details(),
            },
        ))
    }
}

impl OAuth2ParServer for Server {
    async fn par(
        &self,
        request: ServerAuthorizationRequest<Self::AuthParams>,
    ) -> Result<PushedAuthorizationResponse, OAuth2ServerError> {
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

    async fn par_authorize(&self, client_id: ClientId, request_uri: UriBuf) -> impl IntoResponse {
        match self.oauth2.par.remove(&request_uri) {
            Some((_, pa)) => {
                if pa.expires_at < UtcDateTime::now() {
                    return Err(Error::Expired);
                }

                if *pa.request.client_id() != client_id {
                    return Err(Error::Unauthorized);
                }

                Ok(self.authorize(pa.request).await.into_response())
            }
            None => Err(Error::UnknownRequestUrl),
        }
    }
}

pub struct PreAuthorizedCodeMetadata {
    pub tx_code: Option<String>,
}

pub struct AuthorizationCodeMetadata {
    client_id: ClientId,
    redirect_uri: RedirectUrl,
}

pub struct PushedAuthorization {
    request: ServerAuthorizationRequest<CredentialAuthorizationRequestParams>,
    expires_at: UtcDateTime,
}

impl AuthorizationCodeMetadata {
    fn check_request(&self, request: &AuthorizationCodeTokenRequest) -> bool {
        request.client_id == self.client_id && request.redirect_uri == self.redirect_uri
    }
}

pub struct AccessTokenMetadata {
    pub client_id: Option<ClientId>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TokenRequest {
    AuthorizationCode(AuthorizationCodeTokenRequest),
    PreAuthorizedCode(PreAuthorizedCodeTokenRequest),
    RefreshToken(RefreshTokenRequest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum TokenType {
    Bearer,
}

impl oauth2::TokenType for TokenType {}

struct Redirect(Url);

impl IntoResponse for Redirect {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::FOUND)
            .header("Location", self.0.to_string())
            .body(Body::empty())
            .unwrap()
    }
}
