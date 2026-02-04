use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown credential offer")]
    UnknownCredentialOffer,

    #[error("expired")]
    Expired,

    #[error("unauthorized")]
    Unauthorized,

    #[error("missing redirect URL")]
    MissingRedirectUrl,

    #[error("unknown request URL")]
    UnknownRequestUrl,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "text/html")
            .body(Body::from(format!("<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Error</h1><p>{self}</p></body></html>")))
            .unwrap()
    }
}
