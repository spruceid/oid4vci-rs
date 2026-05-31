use std::{borrow::Cow, future::Future, sync::Arc};

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json,
};
use open_auth2::{server::ErrorResponse, AccessTokenBuf};
use serde::{Deserialize, Serialize};

use crate::{
    endpoints::{
        credential::DeferredCredentialRequest,
        nonce::NonceResponse,
        notification::{NotificationError, NotificationRequest},
    },
    profile::{
        ProfileCredentialIssuerMetadata, ProfileCredentialRequest, ProfileCredentialResponse,
    },
    Profile,
};

pub trait Oid4vciServer: Sized + Send + Sync + 'static {
    type Profile: Profile;

    /// Credential Issuer Metadata.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata>
    fn metadata(
        &self,
    ) -> impl Send
           + Future<
        Output = Result<Cow<'_, ProfileCredentialIssuerMetadata<Self::Profile>>, ServerError>,
    >;

    /// Nonce Endpoint.
    ///
    /// The default implementation generates a random 32-bytes long ASCII
    /// alphanumeric string.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint>
    fn nonce(&self) -> impl Send + Future<Output = Result<String, ServerError>> {
        async move {
            let mut rng = rand::rng();
            let nonce: String = rand::Rng::sample_iter(&mut rng, &rand::distr::Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();
            Ok(nonce)
        }
    }

    /// Credential Endpoint.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint>
    fn credential(
        &self,
        headers: HeaderMap,
        access_token: AccessTokenBuf,
        request: ProfileCredentialRequest<Self::Profile>,
    ) -> impl Send + Future<Output = Result<ProfileCredentialResponse<Self::Profile>, ServerError>>;

    /// Deferred Credential Endpoint.
    ///
    /// `headers` carries the request headers so the endpoint can process
    /// header-bound material such as the `DPoP` proof (RFC 9449 §7.1).
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin>
    fn deferred_credential(
        &self,
        _headers: HeaderMap,
        _access_token: AccessTokenBuf,
        _transaction_id: String,
    ) -> impl Send + Future<Output = Result<ProfileCredentialResponse<Self::Profile>, ServerError>>
    {
        async move { Err(ServerError::InvalidNotificationId) }
    }

    /// Notification Endpoint.
    ///
    /// `headers` carries the request headers so the endpoint can process
    /// header-bound material such as the `DPoP` proof (RFC 9449 §7.1).
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-endpoint>
    fn notification(
        &self,
        _headers: HeaderMap,
        _access_token: AccessTokenBuf,
        _notification: NotificationRequest,
    ) -> impl Send + Future<Output = Result<(), ServerError>> {
        async move { Ok(()) }
    }
}

pub trait Oid4vciRouter<S: Oid4vciServer> {
    fn oid4vci_routes(self) -> Self;
}

impl<S: Oid4vciServer> Oid4vciRouter<S> for axum::Router<Arc<S>> {
    fn oid4vci_routes(self) -> Self {
        self.route("/.well-known/openid-credential-issuer", get(metadata::<S>))
            .route("/nonce", post(nonce::<S>))
            .route("/credential", post(credential::<S>))
            .route("/deferred_credential", post(deferred_credential::<S>))
            .route("/notification", post(notification::<S>))
    }
}

/// Credential Issuer Metadata Endpoint.
async fn metadata<S>(State(server): State<Arc<S>>) -> impl IntoResponse
where
    S: Oid4vciServer,
{
    // TODO support `Accept-Language` header.
    server
        .metadata()
        .await
        .map(|metadata| metadata.as_ref().into_response())
}

/// Nonce Endpoint.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint>
async fn nonce<S>(State(server): State<Arc<S>>) -> impl IntoResponse
where
    S: Oid4vciServer,
{
    server
        .nonce()
        .await
        .map(|c_nonce| NonceResponse { c_nonce })
}

/// Extracts the access token from the `Authorization` header, accepting both the
/// `Bearer` (RFC 6750) and `DPoP` (RFC 9449) authentication schemes. The scheme
/// match is case-insensitive (RFC 9110 §11.1).
fn extract_access_token(headers: &HeaderMap) -> Option<AccessTokenBuf> {
    let (scheme, token) = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .split_once(' ')?;

    if !scheme.eq_ignore_ascii_case("bearer") && !scheme.eq_ignore_ascii_case("dpop") {
        return None;
    }

    AccessTokenBuf::new(token.trim().to_owned()).ok()
}

/// Credential Endpoint.
async fn credential<S>(
    State(server): State<Arc<S>>,
    headers: HeaderMap,
    Json(credential_request): Json<ProfileCredentialRequest<S::Profile>>,
) -> Response
where
    S: Oid4vciServer,
{
    let Some(access_token) = extract_access_token(&headers) else {
        return ServerError::Unauthorized.into_response();
    };
    server
        .credential(headers, access_token, credential_request)
        .await
        .into_response()
}

/// Deferred Credential Endpoint.
async fn deferred_credential<S>(
    State(server): State<Arc<S>>,
    headers: HeaderMap,
    Json(credential_request): Json<DeferredCredentialRequest>,
) -> Response
where
    S: Oid4vciServer,
{
    let Some(access_token) = extract_access_token(&headers) else {
        return ServerError::Unauthorized.into_response();
    };
    server
        .deferred_credential(headers, access_token, credential_request.transaction_id)
        .await
        .into_response()
}

/// Notification Endpoint.
async fn notification<S>(
    State(server): State<Arc<S>>,
    headers: HeaderMap,
    Json(notification): Json<NotificationRequest>,
) -> Response
where
    S: Oid4vciServer,
{
    let Some(access_token) = extract_access_token(&headers) else {
        return ServerError::Unauthorized.into_response();
    };
    server
        .notification(headers, access_token, notification)
        .await
        .map(|()| {
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::default())
                // UNWRAP SAFETY: An empty HTTP response is always valid.
                .unwrap()
        })
        .into_response()
}

/// Credential Error Response codes.
///
/// The `error` codes a Credential Issuer returns for an invalid Credential
/// Request, as defined in OpenID4VCI §8.3.1.2.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request-errors>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialErrorCode {
    /// The Credential Request is missing a required parameter, includes an
    /// unsupported parameter or parameter value, repeats the same parameter, or
    /// is otherwise malformed.
    InvalidCredentialRequest,

    /// Requested Credential Configuration is unknown.
    UnknownCredentialConfiguration,

    /// Requested Credential identifier is unknown.
    UnknownCredentialIdentifier,

    /// The `proofs` parameter is invalid: it is missing, one of the key proofs
    /// is invalid, or at least one does not contain a `c_nonce` value.
    InvalidProof,

    /// The `proofs` parameter uses an invalid nonce: at least one of the key
    /// proofs contains an invalid `c_nonce` value.
    InvalidNonce,

    /// The encryption parameters in the Credential Request are invalid or
    /// missing.
    InvalidEncryptionParameters,

    /// The Credential Request has not been accepted by the Credential Issuer.
    CredentialRequestDenied,
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("unauthorized")]
    Unauthorized,

    /// A Credential Request error (OpenID4VCI §8.3.1.2). Rendered as an HTTP 400
    /// response with a JSON `{ "error", "error_description"? }` body.
    #[error("credential request error: {0:?}")]
    CredentialRequest(CredentialErrorCode, Option<String>),

    #[error("invalid notification id")]
    InvalidNotificationId,

    #[error("{0}")]
    Other(String),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized => Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::default())
                .unwrap(),
            // OpenID4VCI §8.3.1.2: HTTP 400, `application/json`, with the error
            // code (and optional description) in the body. Never cached.
            Self::CredentialRequest(error, error_description) => Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CACHE_CONTROL, "no-store")
                .body(Body::from(
                    serde_json::to_vec(&ErrorResponse::new(error, error_description, None))
                        // UNWRAP SAFETY: A Credential Error Response is always
                        //                serializable as JSON.
                        .unwrap(),
                ))
                .unwrap(),
            Self::InvalidNotificationId => Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(
                    serde_json::to_vec(&ErrorResponse::new(
                        NotificationError::InvalidNotificationId,
                        None,
                        None,
                    ))
                    // UNWRAP SAFETY: A Notification Error Response is always
                    //                serializable as JSON.
                    .unwrap(),
                ))
                .unwrap(),
            Self::Other(_) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::default())
                .unwrap(),
        }
    }
}
