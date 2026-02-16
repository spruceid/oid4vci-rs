use std::{borrow::Cow, future::Future, sync::Arc};

use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use open_auth2::{server::ErrorResponse, AccessTokenBuf};

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
        access_token: AccessTokenBuf,
        request: ProfileCredentialRequest<Self::Profile>,
    ) -> impl Send + Future<Output = Result<ProfileCredentialResponse<Self::Profile>, ServerError>>;

    /// Deferred Credential Endpoint.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin>
    fn deferred_credential(
        &self,
        _access_token: AccessTokenBuf,
        _transaction_id: String,
    ) -> impl Send + Future<Output = Result<ProfileCredentialResponse<Self::Profile>, ServerError>>
    {
        async move { Err(ServerError::InvalidNotificationId) }
    }

    /// Deferred Credential Endpoint.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin>
    fn notification(
        &self,
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

/// Credential Endpoint.
async fn credential<S>(
    State(server): State<Arc<S>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    Json(credential_request): Json<ProfileCredentialRequest<S::Profile>>,
) -> impl IntoResponse
where
    S: Oid4vciServer,
{
    let access_token = AccessTokenBuf::new(bearer.token().to_owned()).unwrap();
    server.credential(access_token, credential_request).await
}

/// Deferred Credential Endpoint.
async fn deferred_credential<S>(
    State(server): State<Arc<S>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    Json(credential_request): Json<DeferredCredentialRequest>,
) -> impl IntoResponse
where
    S: Oid4vciServer,
{
    let access_token = AccessTokenBuf::new(bearer.token().to_owned()).unwrap();
    server
        .deferred_credential(access_token, credential_request.transaction_id)
        .await
}

/// Notification Endpoint.
async fn notification<S>(
    State(server): State<Arc<S>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    Json(notification): Json<NotificationRequest>,
) -> impl IntoResponse
where
    S: Oid4vciServer,
{
    let access_token = AccessTokenBuf::new(bearer.token().to_owned()).unwrap();
    server
        .notification(access_token, notification)
        .await
        .map(|()| {
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::default())
                // UNWRAP SAFETY: An empty HTTP response is always valid.
                .unwrap()
        })
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("unauthorized")]
    Unauthorized,

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
