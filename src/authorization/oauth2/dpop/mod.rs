//! RFC 9449 OAuth 2.0 Demonstrating Proof of Possession (DPoP)
//!
//! See: <https://www.rfc-editor.org/rfc/rfc9449>
use std::{borrow::Cow, time::Duration};

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
        jws::{Jws, JwsSigner, JwsSignerInfo, ValidateJwsHeader},
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

/// Clock-skew leeway applied to a DPoP proof's `iat` when accepting a proof
/// minted slightly in the future.
///
/// RFC 9449 §4.3 leaves the acceptable `iat` window to the server; FAPI2
/// requires tolerating reasonable skew between the client's and server's
/// clocks, so a proof up to this far in the future is still accepted.
pub const DPOP_IAT_LEEWAY: Duration = Duration::from_secs(60);

/// DPoP Proof.
///
/// See: <https://www.rfc-editor.org/rfc/rfc9449#section-4.2>
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
    max_age: Option<Duration>,
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

        // RFC 9449 §4.3: the `iat` must not be in the future, tolerating up to
        // `DPOP_IAT_LEEWAY` of clock skew between the client and this server
        // (required by FAPI2) — hence verifying against `now + DPOP_IAT_LEEWAY`.
        self.iat.verify(now + DPOP_IAT_LEEWAY)?;

        // When a max age is configured, a proof older than it is also rejected.
        if let Some(max_age) = params.max_age {
            let age = now.timestamp() as f64 - self.iat.0.as_seconds();
            if age > max_age.as_secs_f64() {
                return Err(InvalidClaims::other("`iat` claim is too old"));
            }
        }

        if params.htm != self.htm {
            return Err(InvalidClaims::other("invalid `htm` claim value"));
        }

        // RFC 9449 §4.3: the `htu` is matched ignoring query and fragment, and
        // per RFC 3986 §6.2.2/§6.2.3 (scheme/host case-insensitive, default port
        // for the scheme normalized).
        if !htu_matches(params.htu, &self.htu) {
            return Err(InvalidClaims::other("invalid `htu` claim value"));
        }

        Ok(())
    }
}

/// Compares two `htu` values for DPoP proof validation.
///
/// Query and fragment are ignored (RFC 9449 §4.3), and the comparison applies
/// RFC 3986 syntax-based normalization: the scheme and host are compared
/// case-insensitively (§6.2.2.1) and a port equal to the scheme's default is
/// treated as absent (§6.2.3).
fn htu_matches(a: &Uri, b: &Uri) -> bool {
    fn normalized(u: &Uri) -> (String, Option<String>, Option<&str>, String) {
        let scheme = u.scheme().as_str().to_ascii_lowercase();
        let authority = u.authority();
        let host = authority.map(|a| a.host().as_str().to_ascii_lowercase());
        let default_port = match scheme.as_str() {
            "https" => Some("443"),
            "http" => Some("80"),
            _ => None,
        };
        let port = authority
            .and_then(|a| a.port())
            .map(|p| p.as_str())
            .filter(|p| Some(*p) != default_port);
        (scheme, host, port, u.path().as_str().to_owned())
    }

    normalized(a) == normalized(b)
}

/// A verified DPoP proof.
#[derive(Debug)]
pub struct VerifiedDpopProof {
    /// The verified proof claims.
    pub proof: DpopProof,

    /// The public key that signed the proof. DPoP proofs are self-signed, so
    /// this key's JWK SHA-256 thumbprint (RFC 7638) is the `jkt` an access token
    /// is bound to (RFC 9449 §6.1).
    pub jwk: JWK,
}

/// Error returned when verifying a DPoP proof.
#[derive(Debug, thiserror::Error)]
#[error("invalid DPoP proof: {0}")]
pub struct DpopVerificationError(String);

/// Verifies a DPoP proof JWT (RFC 9449 §4.3).
///
/// Checks that the proof is a `dpop+jwt` typed JWT, signed (with an asymmetric
/// algorithm) by the key in its `jwk` header, whose `htm`/`htu` match the
/// request and whose `iat` is no older than `max_age`.
///
/// The remaining resource-server checks (RFC 9449 §7.1) are left to the caller,
/// which has the necessary context: that the proof key's thumbprint matches the
/// access token's `jkt`, and that the `ath` claim equals the access token hash.
pub async fn verify_dpop_proof(
    proof: &Jws,
    htm: &str,
    htu: &Uri,
    max_age: Duration,
) -> Result<VerifiedDpopProof, DpopVerificationError> {
    let decoded = proof
        .decode()
        .map_err(|_| DpopVerificationError("undecodable proof".to_owned()))?
        .try_map(|bytes| serde_json::from_slice::<DpopProof>(&bytes))
        .map_err(|_| DpopVerificationError("malformed proof claims".to_owned()))?;

    if decoded.header().type_.as_deref() != Some(DPOP_JWT_TYP) {
        return Err(DpopVerificationError(
            "missing or invalid `typ` header".to_owned(),
        ));
    }

    let jwk = decoded
        .header()
        .jwk
        .clone()
        .ok_or_else(|| DpopVerificationError("missing `jwk` header".to_owned()))?;

    let params = DpopProofVerificationParams {
        key_resolver: jwk.clone(),
        htm,
        htu,
        max_age: Some(max_age),
    };

    match decoded.verify(params).await {
        Ok(Ok(())) => {}
        Ok(Err(invalid)) => return Err(DpopVerificationError(invalid.to_string())),
        Err(e) => return Err(DpopVerificationError(e.to_string())),
    }

    Ok(VerifiedDpopProof {
        proof: decoded.signing_bytes.payload,
        jwk,
    })
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
