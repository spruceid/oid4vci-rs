use std::{borrow::Cow, time::Duration};

use iref::{Uri, UriBuf};
use open_auth2::ClientId;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use ssi::{
    claims::{
        chrono::Utc,
        jws::{JwsSigner, JwsSignerInfo, ValidateJwsHeader},
        jwt::{ClaimSet, ExpirationTime, IssuedAt, NotBefore},
        ClaimsValidity, DateTimeProvider, InvalidClaims, Jws, JwsBuf, JwsPayload,
        ProofValidationError, ResolverProvider, SignatureError, ValidateClaims,
    },
    jwk::JWKResolver,
    JWK,
};

use crate::util::jwt_numeric_date;

use super::VerificationError;

/// JWT proof `typ` JOSE header value.
pub const JWT_PROOF_JOSE_TYP: &str = "openid4vci-proof+jwt";

pub struct JwtProofVerifier<'a, R: ?Sized> {
    pub issuer: &'a Uri,
    pub jwk_resolver: &'a R,
    pub time_tolerance: Option<Duration>,
}

impl<'a, R: ?Sized> JwtProofVerifier<'a, R> {
    pub fn new(issuer: &'a Uri, jwk_resolver: &'a R) -> Self {
        Self {
            issuer,
            jwk_resolver,
            time_tolerance: None,
        }
    }

    pub fn with_time_tolerance(self, t: Duration) -> Self {
        Self {
            time_tolerance: Some(t),
            ..self
        }
    }
}

/// A successfully verified `jwt` key proof.
#[derive(Debug, Clone)]
pub struct VerifiedProof {
    /// The key the Credential is to be cryptographically bound to.
    pub key: JWK,

    /// The `c_nonce` carried by the proof, if any.
    ///
    /// Verifying that this value is a fresh, server-issued nonce (i.e. checking
    /// it against the values handed out by the Nonce Endpoint, and that it has
    /// not expired or been replayed) is the Credential Issuer's responsibility:
    /// it owns the nonce lifecycle, so the policy lives in the application, not
    /// in this stateless verifier. See OpenID4VCI §8.2 (the proof MUST carry a
    /// `c_nonce`) and §8.3.1.2 (`invalid_proof` / `invalid_nonce`).
    pub nonce: Option<String>,
}

impl<R> JwtProofVerifier<'_, R>
where
    R: ?Sized + JWKResolver,
{
    /// Verify a list of JWT proofs.
    ///
    /// Returns, for each proof, the key the Credential is to be bound to and the
    /// `c_nonce` it carried (for the caller to validate against the nonces it
    /// issued).
    pub async fn verify_list(
        &self,
        client_id: Option<&ClientId>,
        jwts: &[JwsBuf],
    ) -> Result<Vec<VerifiedProof>, VerificationError> {
        let mut result = Vec::with_capacity(jwts.len());

        for jwt in jwts {
            result.push(self.verify(client_id, jwt).await?);
        }

        Ok(result)
    }

    /// Verify a JWT proof.
    ///
    /// Returns the key the Credential is to be bound to and the `c_nonce` the
    /// proof carried (for the caller to validate against the nonces it issued).
    pub async fn verify(
        &self,
        client_id: Option<&ClientId>,
        jwt: &Jws,
    ) -> Result<VerifiedProof, VerificationError> {
        let decoded = jwt
            .decode()
            .map_err(|_| ProofValidationError::InvalidProof)?
            .try_map(|bytes| serde_json::from_slice::<JwtProofBody>(&bytes))
            .map_err(|_| ProofValidationError::InvalidProof)?;

        let header = decoded.header();

        let jwk = match (&header.jwk, &header.key_id) {
            (Some(jwk), None) => Cow::Borrowed(jwk),
            (None, Some(kid)) => self.jwk_resolver.fetch_public_jwk(Some(kid)).await?,
            (None, None) => {
                return Err(VerificationError::Failed(
                    ProofValidationError::MissingPublicKey,
                ))
            }
            _ => {
                return Err(VerificationError::Failed(
                    ProofValidationError::AmbiguousPublicKey,
                ))
            }
        };

        let params = VerificationParams {
            issuer: self.issuer,
            jwk: jwk.as_ref(),
            client_id,
            time_tolerance: self.time_tolerance,
        };

        decoded.verify(params).await??;

        let nonce = decoded.signing_bytes.payload.nonce.clone();

        Ok(VerifiedProof {
            key: jwk.into_owned(),
            nonce,
        })
    }
}

pub async fn create_jwt_proof(
    issuer: Option<String>,
    audience: UriBuf,
    expire_in: Option<Duration>,
    nonce: Option<String>,
    signer: impl JwsSigner,
) -> Result<JwsBuf, SignatureError> {
    let now = Utc::now();

    let body = JwtProofBody {
        iss: issuer,
        aud: audience,
        iat: IssuedAt(jwt_numeric_date(now)),
        nbf: None,
        exp: expire_in.map(|d| ExpirationTime(jwt_numeric_date(now + d))),
        nonce,
    };

    body.sign(signer).await
}

/// A [`JwsSigner`] that signs a key proof and embeds the signing key's public
/// JWK in the protected header, clearing any `kid`.
///
/// A `jwt` key proof carries the holder's public key in the JOSE header, where
/// `jwk` and `kid` are mutually exclusive (OpenID4VCI Appendix F.1). Wrap the
/// holder's signing [`JWK`] with this so [`create_jwt_proof`] emits a `jwk`
/// header rather than a `kid`. It is the key-proof counterpart of the DPoP
/// module's [`DpopSigner`](crate::authorization::oauth2::dpop::DpopSigner).
pub struct JwkProofSigner<'a>(pub &'a JWK);

impl JwsSigner for JwkProofSigner<'_> {
    async fn fetch_info(&self) -> Result<JwsSignerInfo, SignatureError> {
        let mut info = self.0.fetch_info().await?;
        // `jwk` and `kid` are mutually exclusive (OpenID4VCI Appendix F.1).
        info.kid = None;
        info.jwk = Some(self.0.to_public());
        Ok(info)
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        self.0.sign_bytes(signing_bytes).await
    }
}

/// JWT body for a `jwt` proof.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type>
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtProofBody {
    /// Client identifier.
    ///
    /// Must be the `client_id` of the client making the Credential Request.
    /// It *must* be omitted if the access token authorizing the issuance call
    /// was obtained from a Pre-Authorized Code Flow through anonymous access to
    /// the Token Endpoint.
    pub iss: Option<String>,

    /// Credential Issuer Identifier.
    pub aud: UriBuf,

    /// Time at which the key proof was issued.
    pub iat: IssuedAt,

    /// Time from which the key proof may be verified.
    pub nbf: Option<NotBefore>,

    /// Proof expiration time.
    pub exp: Option<ExpirationTime>,

    /// Server-provided `c_nonce` value.
    ///
    /// It *must* be present when the issuer has a Nonce Endpoint.
    pub nonce: Option<String>,
}

impl JwsPayload for JwtProofBody {
    fn typ(&self) -> Option<&str> {
        Some(JWT_PROOF_JOSE_TYP)
    }

    fn payload_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

impl ClaimSet for JwtProofBody {}

struct VerificationParams<'a> {
    jwk: &'a JWK,
    issuer: &'a Uri,
    client_id: Option<&'a ClientId>,
    time_tolerance: Option<Duration>,
}

impl ResolverProvider for VerificationParams<'_> {
    type Resolver = JWK;

    fn resolver(&self) -> &Self::Resolver {
        self.jwk
    }
}

impl DateTimeProvider for VerificationParams<'_> {
    fn date_time(&self) -> ssi::claims::chrono::DateTime<ssi::claims::chrono::Utc> {
        ssi::claims::chrono::Utc::now()
    }
}

impl ValidateJwsHeader<VerificationParams<'_>> for JwtProofBody {}

impl<S> ValidateClaims<VerificationParams<'_>, S> for JwtProofBody {
    fn validate_claims(&self, params: &VerificationParams<'_>, _proof: &S) -> ClaimsValidity {
        let now = params.date_time();

        let time_tolerance = params.time_tolerance.unwrap_or_default();

        if let Some(not_before) = self.nbf {
            not_before.verify(now + time_tolerance)?;
        }

        if let Some(expires_at) = self.exp {
            expires_at.verify(now - time_tolerance)?;
        }

        if self.iss.as_deref() != params.client_id.map(|c| c.as_str()) {
            return Err(InvalidClaims::Other("Invalid issuer".to_owned()));
        }

        if self.aud != params.issuer {
            return Err(InvalidClaims::Other("Invalid audience".to_owned()));
        }

        Ok(())
    }
}
