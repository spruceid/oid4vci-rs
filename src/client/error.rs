use open_auth2::client::OAuth2ClientError;
use ssi::claims::SignatureError;

use crate::offer::CredentialOfferError;

/// Client error.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    OAuth2(#[from] OAuth2ClientError),

    /// Error with the credential offer.
    #[error(transparent)]
    CredentialOffer(#[from] CredentialOfferError),

    /// The credential offer doesn't have any grant, and the client doesn't
    /// have any built-in grant.
    #[error("missing grant")]
    MissingGrant,

    #[error("no configured client attestation")]
    NoClientAttestation,

    #[error("client attestation PoP signature failed: {0}")]
    ClientAttestationPopSignatureFailed(SignatureError),

    #[error("missing authorization server")]
    MissingAuthorizationServer,

    #[error("ambiguous authorization server")]
    AmbiguousAuthorizationServer,

    #[error("invalid authorization server")]
    InvalidAuthorizationServer,

    #[error("missing authorization endpoint")]
    MissingAuthorizationEndpoint,

    #[error("missing token endpoint")]
    MissingTokenEndpoint,

    #[error("authorization failed")]
    Authorization,

    /// The wallet is lost and doesn't know what credential to pick.
    #[error("ambiguous credential offer")]
    AmbiguousCredentialOffer,

    #[error("{0}")]
    Other(String),
}
