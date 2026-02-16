//! RFC 9449 OAuth 2.0 Demonstrating Proof of Possession (DPoP)
//!
//! See: <https://www.rfc-editor.org/rfc/rfc9449>
use std::borrow::Cow;

use iref::{Uri, UriBuf};
use open_auth2::http::{self, HeaderName, HeaderValue};
use rand::{
    distr::{Alphanumeric, SampleString},
    rng,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use ssi::{
    claims::{
        jws::{JwsSigner, JwsSignerInfo, ValidateJwsHeader},
        jwt::{ClaimSet, IssuedAt},
        ClaimsValidity, DateTimeProvider, InvalidClaims, JwsBuf, JwsPayload, ResolverProvider,
        SignatureError, ValidateClaims,
    },
    jwk::Algorithm,
    JWK,
};
use str_newtype::StrNewType;

use crate::util::jwt_iat_now;

mod client;
mod server;

pub use client::*;
pub use server::*;

/// DPoP HTTP Header.
///
/// See: <https://www.rfc-editor.org/rfc/rfc9449#name-the-dpop-http-header>
pub const DPOP: HeaderName = HeaderName::from_static("dpop");

/// Server-Provided DPoP Nonce HTTP Header.
///
/// See: <https://www.rfc-editor.org/rfc/rfc9449#name-authorization-server-provid>
pub const DPOP_NONCE: HeaderName = HeaderName::from_static("dpop-nonce");

/// DPoP Proof JWT `typ` claim value.
pub const DPOP_JWT_TYP: &str = "dpop+jwt";

/// DPoP Proof.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#name-client-attestation-jwt>
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
pub struct DpopProof {
    /// Unique identifier for the DPoP proof JWT.
    ///
    /// The value *must* be assigned such that there is a negligible probability
    /// that the same value will be assigned to any other DPoP proof used in the
    /// same context during the time window of validity.
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9449#Token_Replay>
    pub jti: String,

    /// Value of the HTTP method of the request to which the JWT is attached.
    ///
    /// See: <https://rfc-editor.org/rfc/rfc9110#section-9.1>
    pub htm: String,

    /// HTTP target URI of the request to which the JWT is attached, without the
    /// query and fragment part.
    ///
    /// See: <https://rfc-editor.org/rfc/rfc9110#section-7.1>
    pub htu: UriBuf,

    /// Creation timestamp of the JWT.
    ///
    /// See: <https://rfc-editor.org/rfc/rfc7519#section-4.1.6>
    pub iat: IssuedAt,

    /// Hash of the access token.
    ///
    /// The value *must* be the result of a base64url encoding the SHA-256 hash
    /// of the ASCII encoding of the associated access token's value.
    ///
    /// Set when the DPoP proof is used in conjunction with the presentation of
    /// an access token in protected resource access.
    pub ath: Option<String>,

    /// Recent nonce provided via the DPoP-Nonce HTTP header.
    pub nonce: Option<String>,
}

impl DpopProof {
    pub fn new(htm: String, htu: UriBuf, ath: Option<String>, nonce: Option<String>) -> Self {
        Self {
            jti: Alphanumeric.sample_string(&mut rng(), 30),
            htm,
            htu,
            iat: jwt_iat_now(),
            ath,
            nonce,
        }
    }

    pub async fn sign(
        &self,
        signer: DpopSigner<'_, impl JwsSigner>,
    ) -> Result<JwsBuf, SignatureError> {
        JwsPayload::sign(self, signer).await
    }
}

pub struct DpopSigner<'a, S> {
    inner: &'a S,
    public_jwk: &'a JWK,
}

impl<'a, S> Clone for DpopSigner<'a, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, S> Copy for DpopSigner<'a, S> {}

impl<'a, S> DpopSigner<'a, S> {
    pub fn new(inner: &'a S, public_jwk: &'a JWK) -> Self {
        Self { inner, public_jwk }
    }
}

impl<'a, S> JwsSigner for DpopSigner<'a, S>
where
    S: JwsSigner,
{
    async fn fetch_info(&self) -> Result<JwsSignerInfo, SignatureError> {
        let mut info = self.inner.fetch_info().await?;
        info.jwk = Some(self.public_jwk.clone());
        Ok(info)
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        self.inner.sign_bytes(signing_bytes).await
    }
}

impl JwsPayload for DpopProof {
    fn typ(&self) -> Option<&str> {
        Some(DPOP_JWT_TYP)
    }

    fn payload_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

impl ClaimSet for DpopProof {}

struct DpopProofVerificationParams<'a, K> {
    key_resolver: K,
    htm: &'a str,
    htu: &'a Uri,
}

impl<K> ResolverProvider for DpopProofVerificationParams<'_, K> {
    type Resolver = K;

    fn resolver(&self) -> &Self::Resolver {
        &self.key_resolver
    }
}

impl<K> DateTimeProvider for DpopProofVerificationParams<'_, K> {
    fn date_time(&self) -> ssi::claims::chrono::DateTime<ssi::claims::chrono::Utc> {
        ssi::claims::chrono::Utc::now()
    }
}

impl<K> ValidateJwsHeader<DpopProofVerificationParams<'_, K>> for DpopProof {
    fn validate_jws_header(
        &self,
        _env: &DpopProofVerificationParams<'_, K>,
        header: &ssi::claims::jws::Header,
    ) -> ClaimsValidity {
        if header.algorithm == Algorithm::None {
            Err(InvalidClaims::other("invalid `alg` header field"))
        } else {
            Ok(())
        }
    }
}

impl<K, S> ValidateClaims<DpopProofVerificationParams<'_, K>, S> for DpopProof {
    fn validate_claims(
        &self,
        params: &DpopProofVerificationParams<'_, K>,
        _proof: &S,
    ) -> ClaimsValidity {
        let now = params.date_time();
        self.iat.verify(now)?;

        if params.htm != self.htm {
            return Err(InvalidClaims::other("invalid `htm` claim value"));
        }

        if *params.htu != self.htu {
            return Err(InvalidClaims::other("invalid `htu` claim value"));
        }

        Ok(())
    }
}

#[derive(StrNewType)]
#[newtype(owned(DpopNonceBuf))]
#[repr(transparent)]
pub struct DpopNonce(str);

impl DpopNonce {
    pub const fn validate_str(s: &str) -> bool {
        Self::validate_bytes(s.as_bytes())
    }

    pub const fn validate_bytes(bytes: &[u8]) -> bool {
        let mut i = 0;

        const fn is_nqchar(c: u8) -> bool {
            c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e)
        }

        while i < bytes.len() {
            if !is_nqchar(bytes[i]) {
                return false;
            }

            i += 1;
        }

        !bytes.is_empty()
    }
}

impl From<DpopNonceBuf> for HeaderValue {
    fn from(value: DpopNonceBuf) -> Self {
        value
            .0
            .try_into()
            // UNWRAP SAFETY: By construction a DPoP Nonce is a valid HTTP
            //                header value.
            .unwrap()
    }
}

pub trait DpopRequest {
    fn insert_dpop(&mut self, dpop: JwsBuf);
}

impl<B> DpopRequest for http::Request<B> {
    fn insert_dpop(&mut self, dpop: JwsBuf) {
        self.headers_mut()
            .insert(DPOP, dpop.into_string().try_into().unwrap());
    }
}

pub trait DpopResponse {
    fn insert_dpop_nonce(&mut self, nonce: DpopNonceBuf);
}

impl<B> DpopResponse for http::Response<B> {
    fn insert_dpop_nonce(&mut self, nonce: DpopNonceBuf) {
        self.headers_mut().insert(DPOP_NONCE, nonce.into());
    }
}
