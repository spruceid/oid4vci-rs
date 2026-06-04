use core::fmt;
use std::{borrow::Cow, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use base64::Engine as _;
use dashmap::DashMap;
use iref::UriBuf;
use oid4vci::{
    authorization::{
        oauth2::{
            client_attestation::{
                ClientAttestationAndPopRef, OAUTH_CLIENT_ATTESTATION, OAUTH_CLIENT_ATTESTATION_POP,
            },
            dpop::DPOP,
        },
        server::{Oid4VciAuthorizationServerParams, Oid4vciAuthorizationServerMetadata},
    },
    client::Oid4vciTokenParams,
};
use open_auth2::{
    endpoints::{
        pushed_authorization::{PushedAuthorizationRequest, PushedAuthorizationResponse},
        token::TokenResponse,
    },
    grant::{
        authorization_code::AuthorizationCodeAuthorizationRequest,
        pre_authorized_code::PreAuthorizedCodeTokenRequest,
    },
    server::{ErrorCode, ErrorResponse, OAuth2Server, OAuth2ServerError},
    AccessToken, AccessTokenBuf, ClientId, ClientIdBuf, CodeBuf, Stateful,
};
use rand::{
    distr::{Alphanumeric, SampleString},
    rng,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use sha2::{Digest, Sha256};
use ssi::claims::jws::Jws;
use time::UtcDateTime;

use crate::{Error, Server};

/// Authorization code lifetime. FAPI2 §5.3.2.1-11 requires short-lived codes;
/// the conformance suite expects expiry within ~60s.
const AUTHORIZATION_CODE_TTL: Duration = Duration::from_secs(60);

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
        dpop_jkt: Option<String>,
        code_challenge: String,
    ) -> Result<Redirect, Error> {
        match request.redirect_url(None).map(ToOwned::to_owned) {
            Some(redirect_uri) => {
                let client_id = request.client_id.clone();
                let code = CodeBuf::new(Alphanumeric.sample_string(&mut rng(), 30)).unwrap();
                let full_redirect_uri = request.grant(state, code.clone(), None).unwrap();

                // RFC 9207 / FAPI2 §5.3.2.2: the authorization response MUST carry
                // the issuer identifier so the wallet can detect mix-up attacks.
                let iss = serde_urlencoded::to_string([(
                    "iss",
                    self.config.credential_issuer().as_str(),
                )])
                .unwrap();
                let redirect_str = full_redirect_uri.as_str();
                let sep = if redirect_str.contains('?') { '&' } else { '?' };
                let full_redirect_uri =
                    UriBuf::new(format!("{redirect_str}{sep}{iss}").into_bytes()).unwrap();

                let m = AuthorizationCodeMetadata {
                    client_id,
                    redirect_uri,
                    // Carry the DPoP key binding established at PAR so the token
                    // endpoint can enforce it (RFC 9449 §10.1).
                    dpop_jkt,
                    // Carry the PKCE challenge so the token endpoint can verify
                    // the code_verifier (RFC 7636 §4.6).
                    code_challenge,
                    // Authorization codes are short-lived (FAPI2 §5.3.2.1-11).
                    expires_at: UtcDateTime::now() + AUTHORIZATION_CODE_TTL,
                };

                self.oauth2.authorization_code.insert(code, m);

                Ok(Redirect(full_redirect_uri))
            }
            None => Err(Error::MissingRedirectUrl),
        }
    }

    /// Renders the interactive approve/deny consent page for `manual_consent`
    /// mode. The links carry the decision to `/authorize/decision`, which is
    /// where the `request_uri` is finally consumed.
    fn consent_page(&self, request_uri: &iref::Uri) -> Html<String> {
        let query = serde_urlencoded::to_string([("request_uri", request_uri.as_str())]).unwrap();
        let base = self.config.credential_issuer();
        Html(format!(
            "<!DOCTYPE html><html><head><title>Authorize</title></head><body>\
             <h1>Authorization Request</h1>\
             <p>The client is requesting authorization.</p>\
             <p><a href=\"{base}/authorize/decision?{query}&amp;decision=approve\">Approve</a></p>\
             <p><a href=\"{base}/authorize/decision?{query}&amp;decision=deny\">Deny</a></p>\
             </body></html>"
        ))
    }

    /// Authenticates the client with Attestation-Based Client Authentication
    /// (ATCA draft-07 §6): the `OAuth-Client-Attestation` and
    /// `OAuth-Client-Attestation-PoP` HTTP headers must carry a Client
    /// Attestation signed by our trusted attester and a PoP signed by the
    /// attested key, both with claims matching this request.
    ///
    /// The advertised `token_endpoint_auth_methods_supported` is
    /// `attest_jwt_client_auth`, so this authentication is mandatory.
    async fn authenticate_client(
        &self,
        headers: &HeaderMap,
        client_id: &ClientId,
    ) -> Result<(), String> {
        let header_str = |name: &_| headers.get(name).and_then(|v| v.to_str().ok());

        let (Some(attestation), Some(pop)) = (
            header_str(&OAUTH_CLIENT_ATTESTATION),
            header_str(&OAUTH_CLIENT_ATTESTATION_POP),
        ) else {
            return Err("missing client attestation headers".to_owned());
        };

        let attestation = Jws::new(attestation).map_err(|_| "malformed attestation JWT")?;
        let pop = Jws::new(pop).map_err(|_| "malformed attestation PoP JWT")?;

        ClientAttestationAndPopRef {
            client_attestation: attestation,
            client_attestation_pop: pop,
        }
        // The attestation `sub` must be `client_id`, and the PoP `aud` is this
        // Authorization Server's issuer identifier.
        .verify(
            &self.attester_jwk,
            None,
            client_id,
            self.config.credential_issuer().as_str(),
            None,
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
    }
}

/// Returns the JWK SHA-256 thumbprint (RFC 7638) of the key in the `DPoP` proof
/// header, if a DPoP proof is present. This is the `jkt` an access token issued
/// for the request is bound to (RFC 9449).
fn dpop_header_jkt(headers: &HeaderMap) -> Result<Option<String>, String> {
    let Some(dpop) = headers.get(&DPOP).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };

    let dpop = Jws::new(dpop).map_err(|_| "malformed DPoP proof")?;
    let decoded = dpop.decode().map_err(|_| "undecodable DPoP proof")?;
    let jwk = decoded
        .header()
        .jwk
        .as_ref()
        .ok_or("DPoP proof is missing its `jwk` header")?;

    jwk.thumbprint().map(Some).map_err(|e| e.to_string())
}

/// `dpop_jkt` PAR parameter (RFC 9449 §10.1), parsed on its own so the rest of
/// the form deserializes independently of this DPoP extension.
#[derive(Deserialize, Default)]
struct DpopJktParam {
    dpop_jkt: Option<String>,
}

/// Used to detect a `request_uri` parameter, which RFC 9126 §2.1 forbids in a
/// PAR request.
#[derive(Deserialize, Default)]
struct RequestUriParam {
    request_uri: Option<String>,
}

/// PKCE parameters (RFC 7636), required with `S256` by FAPI2 §5.2.2-18.
#[derive(Deserialize, Default)]
struct PkceParams {
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

/// `response_type` parameter, read on its own because `serde_urlencoded` does
/// not enforce the internally-tagged `response_type=code` discriminator on
/// [`AuthorizationCodeAuthorizationRequest`].
#[derive(Deserialize, Default)]
struct ResponseTypeParam {
    response_type: Option<String>,
}

/// Pushed Authorization Request endpoint.
///
/// Wraps the OAuth2 PAR handling with the request-level checks the AS must
/// perform before accepting a pushed request: Attestation-Based Client
/// Authentication (ATCA draft-07 §6) from the request headers, and the
/// `dpop_jkt`/DPoP-proof binding cross-check (RFC 9449 §10.1). On failure the AS
/// responds `invalid_client` / `invalid_request` (the suite accepts 400/401).
///
/// The raw body is parsed directly (rather than via `Form`) so the `dpop_jkt`
/// DPoP extension parameter can be read alongside the standard request.
pub async fn par(State(server): State<Arc<Server>>, headers: HeaderMap, body: String) -> Response {
    let request: Stateful<AuthorizationCodeAuthorizationRequest> =
        match serde_urlencoded::from_str(&body) {
            Ok(request) => request,
            Err(e) => {
                log::warn!("PAR: malformed request: {e}");
                return OAuth2ServerError::InvalidRequest.into_response();
            }
        };

    // RFC 9126 §2.1: a PAR request MUST NOT contain a `request_uri` parameter.
    if serde_urlencoded::from_str::<RequestUriParam>(&body)
        .ok()
        .and_then(|p| p.request_uri)
        .is_some()
    {
        log::warn!("PAR: request must not contain a `request_uri` parameter");
        return OAuth2ServerError::InvalidRequest.into_response();
    }

    // FAPI2 §5.3.2.2: only `response_type=code` is permitted. Anything else
    // (e.g. `code id_token`, which would return an `id_token` through the
    // browser) MUST be rejected (RFC 6749 §4.1.2.1 `unsupported_response_type`).
    let response_type = serde_urlencoded::from_str::<ResponseTypeParam>(&body)
        .ok()
        .and_then(|p| p.response_type);
    if response_type.as_deref() != Some("code") {
        log::warn!("PAR: unsupported response_type {response_type:?}");
        return OAuth2ServerError::InvalidRequest.into_response();
    }

    // FAPI2 §5.2.2-18 / RFC 7636: PKCE with the `S256` method is mandatory.
    let pkce = serde_urlencoded::from_str::<PkceParams>(&body).unwrap_or_default();
    let code_challenge = match pkce.code_challenge {
        Some(c) if pkce.code_challenge_method.as_deref() == Some("S256") => c,
        _ => {
            log::warn!(
                "PAR: missing PKCE `code_challenge` or `code_challenge_method` is not `S256`"
            );
            return OAuth2ServerError::InvalidRequest.into_response();
        }
    };

    // FAPI2 §5.3.1.1 / RFC 6749 §3.1.2.3: a `redirect_uri` that is not registered
    // for the client MUST be rejected here — the AS must NOT redirect to it.
    let registered = &server.config.registered_redirect_uris;
    if !registered.is_empty()
        && !matches!(&request.value.redirect_uri, Some(uri) if registered.contains(uri))
    {
        log::warn!(
            "PAR: unregistered redirect_uri {:?}",
            request.value.redirect_uri
        );
        return OAuth2ServerError::InvalidRequest.into_response();
    }

    if let Err(e) = server
        .authenticate_client(&headers, &request.value.client_id)
        .await
    {
        log::warn!("PAR: client authentication failed: {e}");
        return OAuth2ServerError::InvalidClient.into_response();
    }

    // Determine the DPoP key the request binds to (RFC 9449 §10.1): the `DPoP`
    // proof presented at PAR and/or the `dpop_jkt` parameter. If both are given
    // they MUST agree. The resulting thumbprint is carried forward so the token
    // endpoint can enforce that the same key is used.
    let proof_jkt = match dpop_header_jkt(&headers) {
        Ok(jkt) => jkt,
        Err(e) => {
            log::warn!("PAR: invalid DPoP proof: {e}");
            return OAuth2ServerError::InvalidRequest.into_response();
        }
    };
    let param_jkt = serde_urlencoded::from_str::<DpopJktParam>(&body)
        .ok()
        .and_then(|p| p.dpop_jkt);

    if let (Some(param), Some(proof)) = (&param_jkt, &proof_jkt) {
        if param != proof {
            log::warn!("PAR: dpop_jkt `{param}` does not match DPoP proof key `{proof}`");
            return OAuth2ServerError::InvalidRequest.into_response();
        }
    }

    let dpop_jkt = param_jkt.or(proof_jkt);

    server
        .push_authorization_request(request, dpop_jkt, code_challenge)
        .into_response()
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
                // FAPI2 / RFC 9126: this AS requires pushed authorization
                // requests, so a direct authorization request (no `request_uri`)
                // is an `invalid_request`. Report the error by redirecting to a
                // registered redirect_uri (RFC 6749 §4.1.2.1); if none is valid,
                // surface it as an error page instead of redirecting.
                let registered = &self.config.registered_redirect_uris;
                let redirect_ok = matches!(
                    &request.redirect_uri,
                    Some(uri) if registered.is_empty() || registered.contains(uri)
                );

                if redirect_ok {
                    let error = ErrorResponse::new(ErrorCode::InvalidRequest, None, None);
                    match request.deny(state, error, None) {
                        Some(uri) => Redirect(uri).into_response(),
                        None => Error::InvalidRequest.into_response(),
                    }
                } else {
                    Error::InvalidRequest.into_response()
                }
            }
            AuthorizationRequest::Pushed(request) => {
                // Validate the pushed request. In manual-consent mode we only
                // *peek* (the `request_uri` must stay reusable until the user
                // decides); otherwise we consume it and approve immediately.
                if self.config.manual_consent {
                    match self.oauth2.par.get(&request.request_uri) {
                        Some(pa) => {
                            if pa.expires_at < UtcDateTime::now() {
                                return Error::Expired.into_response();
                            }
                            if *pa.request.client_id != request.client_id {
                                return Error::Unauthorized.into_response();
                            }
                            self.consent_page(&request.request_uri).into_response()
                        }
                        None => Error::UnknownRequestUrl.into_response(),
                    }
                } else {
                    match self.oauth2.par.remove(&request.request_uri) {
                        Some((_, pa)) => {
                            if pa.expires_at < UtcDateTime::now() {
                                return Error::Expired.into_response();
                            }
                            if *pa.request.client_id != request.client_id {
                                return Error::Unauthorized.into_response();
                            }
                            self.authorize_direct(pa.request, pa.dpop_jkt, pa.code_challenge)
                                .await
                                .into_response()
                        }
                        None => Error::UnknownRequestUrl.into_response(),
                    }
                }
            }
        }
    }

    async fn token(
        &self,
        headers: HeaderMap,
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
                    // The pre-authorized code flow here is not DPoP-bound.
                    jkt: None,
                }
            }
            TokenRequest::AuthorizationCode(request) => {
                // Consume the authorization code: it is single-use (RFC 6749
                // §4.1.2). An unknown or already-used code is `invalid_grant`
                // (RFC 6749 §5.2).
                let (_, m) = self
                    .oauth2
                    .authorization_code
                    .remove(&request.code)
                    .ok_or(OAuth2ServerError::InvalidGrant)?;

                // FAPI2 §5.3.2.1-11: reject an expired authorization code.
                if m.expires_at < UtcDateTime::now() {
                    log::warn!("token: authorization code expired");
                    return Err(OAuth2ServerError::InvalidGrant);
                }

                // RFC 6749 §5.2: an authorization code presented with a
                // mismatched `client_id` or `redirect_uri` (i.e. that was issued
                // to another client / for another redirect URI) is `invalid_grant`.
                if !m.check_request(&request) {
                    log::warn!(
                        "token: authorization code does not match the request's client_id/redirect_uri"
                    );
                    return Err(OAuth2ServerError::InvalidGrant);
                }

                // RFC 7636 §4.6: verify the PKCE `code_verifier` against the
                // `S256` challenge captured at PAR. A missing or non-matching
                // verifier is `invalid_grant`.
                let pkce_ok = request.code_verifier.as_deref().is_some_and(|verifier| {
                    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(Sha256::digest(verifier.as_bytes()));
                    computed == m.code_challenge
                });
                if !pkce_ok {
                    log::warn!("token: missing or invalid PKCE code_verifier");
                    return Err(OAuth2ServerError::InvalidGrant);
                }

                // The authorization code is bound to the client that obtained it.
                // When the request authenticates with a Client Attestation, it
                // MUST be for that same client (its `sub` must equal the code's
                // client). Using another client's credentials is `invalid_grant`
                // (RFC 6749 §4.1.3 / §5.2).
                if headers.contains_key(&OAUTH_CLIENT_ATTESTATION) {
                    if let Err(e) = self.authenticate_client(&headers, &m.client_id).await {
                        log::warn!(
                            "token: client attestation not bound to the authorization code: {e}"
                        );
                        return Err(OAuth2ServerError::InvalidGrant);
                    }
                }

                // RFC 9449 §5: the access token is DPoP-bound to the key of the
                // DPoP proof presented at the token endpoint. The thumbprint of
                // that key becomes the token's `jkt`.
                let proof_jkt = match dpop_header_jkt(&headers) {
                    Ok(jkt) => jkt,
                    Err(e) => {
                        log::warn!("token: invalid DPoP proof: {e}");
                        return Err(OAuth2ServerError::InvalidRequest);
                    }
                };

                // FAPI2 §5.3.2.2: access tokens MUST be sender-constrained. This
                // issuer uses DPoP (RFC 9449) as its holder-of-key mechanism, so
                // an authorization_code token request MUST present a DPoP proof —
                // without one the AS cannot bind the token and rejects the request
                // rather than issue a bearer token.
                if proof_jkt.is_none() {
                    log::warn!(
                        "token: missing DPoP proof; FAPI2 requires a holder-of-key (DPoP) proof"
                    );
                    return Err(OAuth2ServerError::InvalidRequest);
                }

                // RFC 9449 §10.1: if the request was pre-bound at PAR via
                // `dpop_jkt`, the token proof's key MUST match it.
                if let Some(par_jkt) = &m.dpop_jkt {
                    if proof_jkt.as_ref() != Some(par_jkt) {
                        log::warn!(
                            "token: DPoP proof key does not match the key bound at PAR `{par_jkt}`"
                        );
                        return Err(OAuth2ServerError::InvalidGrant);
                    }
                }

                // Bind the access token to the client that performed the
                // authorization (carried by the authorization code), not the
                // token request body — under Attestation-Based Client
                // Authentication the body omits `client_id`. Carry the DPoP key
                // binding (RFC 9449) so the resource server can enforce it.
                AccessTokenMetadata {
                    client_id: Some(m.client_id),
                    jkt: proof_jkt.or(m.dpop_jkt),
                }
            }
        };

        // A DPoP-bound token (RFC 9449) is advertised with the `DPoP` token type.
        let token_type = if m.jkt.is_some() {
            TokenType::Dpop
        } else {
            TokenType::Bearer
        };

        let access_token = AccessTokenBuf::new(Alphanumeric.sample_string(&mut rng(), 30)).unwrap();
        self.oauth2.access_tokens.insert(access_token.to_owned(), m);

        let mut response = TokenResponse::new(
            access_token,
            token_type,
            Oid4vciTokenParams {
                authorization_details: self.config.authorization_details().into(),
            },
        );
        // RFC 6749 §5.1 recommends advertising the access token lifetime.
        response.expires_in = Some(3600);

        Ok(response)
    }
}

impl Server {
    /// Stores a pushed authorization request and returns its `request_uri`
    /// (RFC 9126). `dpop_jkt` is the DPoP key thumbprint the request is bound to,
    /// if any, carried through to the issued authorization code (RFC 9449 §10.1).
    fn push_authorization_request(
        &self,
        request: Stateful<AuthorizationCodeAuthorizationRequest>,
        dpop_jkt: Option<String>,
        code_challenge: String,
    ) -> PushedAuthorizationResponse {
        log::info!("push request: {request:#?}");

        let request_uri = UriBuf::new(
            format!(
                "urn:ietf:params:oauth:request_uri:{}",
                Alphanumeric.sample_string(&mut rng(), 30)
            )
            .into_bytes(),
        )
        .unwrap();
        // Short-lived request URI (RFC 9126 §2.2 recommends a short lifetime).
        // Kept small so the `request_uri` expiry conformance test does not have
        // to sleep for long.
        let expires_in = 90;
        let expires_at = UtcDateTime::now() + Duration::from_secs(expires_in);

        self.oauth2.par.insert(
            request_uri.clone(),
            PushedAuthorization {
                request,
                expires_at,
                dpop_jkt,
                code_challenge,
            },
        );

        PushedAuthorizationResponse {
            request_uri,
            expires_in,
        }
    }
}

pub struct PreAuthorizedCodeMetadata {
    pub tx_code: Option<String>,
}

pub struct AuthorizationCodeMetadata {
    client_id: ClientIdBuf,
    redirect_uri: UriBuf,
    dpop_jkt: Option<String>,
    code_challenge: String,
    expires_at: UtcDateTime,
}

pub struct PushedAuthorization {
    request: Stateful<AuthorizationCodeAuthorizationRequest>,
    expires_at: UtcDateTime,
    dpop_jkt: Option<String>,
    code_challenge: String,
}

impl AuthorizationCodeMetadata {
    fn check_request(&self, request: &AuthorizationCodeTokenRequest) -> bool {
        // `client_id` in the token request body is only REQUIRED when the client
        // is not otherwise authenticating (RFC 6749 §4.1.3). With Attestation-
        // Based Client Authentication the client authenticates via the Client
        // Attestation, so the body omits `client_id`; only enforce it if present.
        request
            .client_id
            .as_ref()
            .map_or(true, |id| id == &self.client_id)
            && request.redirect_uri.as_ref() == Some(&self.redirect_uri)
    }
}

pub struct AccessTokenMetadata {
    pub client_id: Option<ClientIdBuf>,

    /// JWK thumbprint (RFC 7638) the access token is DPoP-bound to, if any
    /// (RFC 9449). When set, the resource server requires a matching DPoP proof.
    pub jkt: Option<String>,
}

/// Authorization Code grant token request.
///
/// open_auth2 models PKCE (RFC 7636) as a client-side extension and keeps its
/// core `AuthorizationCodeTokenRequest` PKCE-agnostic, so — being the server —
/// we carry the `code_verifier` (§4.5) on our own request type here.
#[skip_serializing_none]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "grant_type", rename = "authorization_code")]
pub struct AuthorizationCodeTokenRequest {
    pub client_id: Option<ClientIdBuf>,
    pub code: CodeBuf,
    pub redirect_uri: Option<UriBuf>,
    pub code_verifier: Option<String>,
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
    /// RFC 9449: a DPoP-bound access token.
    #[serde(rename = "DPoP")]
    Dpop,
}

impl TokenType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Bearer => "Bearer",
            Self::Dpop => "DPoP",
        }
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

/// User decision relayed from the `manual_consent` page.
#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Decision {
    Approve,
    Deny,
}

/// `/authorize/decision` query parameters.
#[derive(Deserialize)]
pub struct DecisionParams {
    request_uri: UriBuf,
    decision: Decision,
}

/// Completes an interactive authorization (`manual_consent` mode).
///
/// This is where the `request_uri` is finally consumed. On approval it issues
/// the authorization code exactly like the auto-approving flow; on denial it
/// redirects with `error=access_denied` (RFC 6749 §4.1.2.1).
pub async fn authorize_decision(
    State(server): State<Arc<Server>>,
    Query(params): Query<DecisionParams>,
) -> Response {
    let Some((_, pa)) = server.oauth2.par.remove(&params.request_uri) else {
        return Error::UnknownRequestUrl.into_response();
    };

    if pa.expires_at < UtcDateTime::now() {
        return Error::Expired.into_response();
    }

    match params.decision {
        Decision::Approve => server
            .authorize_direct(pa.request, pa.dpop_jkt, pa.code_challenge)
            .await
            .into_response(),
        Decision::Deny => {
            let Stateful {
                state,
                value: request,
            } = pa.request;
            // RFC 6749 §4.1.2.1: the resource owner denying the request is
            // reported to the client as `access_denied`.
            let error = ErrorResponse::new("access_denied".to_owned(), None, None);
            match request.deny(state, error, None) {
                Some(uri) => Redirect(uri).into_response(),
                None => Error::MissingRedirectUrl.into_response(),
            }
        }
    }
}
