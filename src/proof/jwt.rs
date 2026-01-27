/// JWT proof `typ` JOSE header value.
pub const JWT_PROOF_JOSE_TYP: &str = "openid4vci-proof+jwt";

#[cfg(feature = "ssi")]
pub use ssi::*;

#[cfg(feature = "ssi")]
mod ssi {
    use std::{borrow::Cow, time::Duration};

    use iref::{Uri, UriBuf};
    use oauth2::ClientId;
    use serde::{Deserialize, Serialize};
    use serde_with::skip_serializing_none;
    use ssi::{
        claims::{
            chrono::{DateTime, Utc},
            cose::ValidateCoseHeader,
            jws::{JwsSigner, ValidateJwsHeader},
            jwt::ClaimSet,
            ClaimsValidity, DateTimeProvider, InvalidClaims, Jws, JwsBuf, JwsPayload,
            ProofValidationError, ResolverProvider, SignatureError, ValidateClaims,
        },
        jwk::JWKResolver,
        JWK,
    };

    use super::{super::VerificationError, JWT_PROOF_JOSE_TYP};

    pub struct JwtProofVerifier<'a, R> {
        pub issuer: &'a Uri,
        pub jwk_resolver: &'a R,
        pub time_tolerance: Option<Duration>,
    }

    impl<'a, R> JwtProofVerifier<'a, R> {
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

    impl<R> JwtProofVerifier<'_, R>
    where
        R: JWKResolver,
    {
        /// Verify a list of JWT proofs.
        ///
        /// Returns the list of keys the credential is to be bound to.
        pub async fn verify_list(
            &self,
            client_id: Option<&ClientId>,
            jwts: &[String],
        ) -> Result<Vec<JWK>, VerificationError> {
            let mut result = Vec::with_capacity(jwts.len());

            for jwt in jwts {
                result.push(self.verify(client_id, jwt).await?);
            }

            Ok(result)
        }

        /// Verify a JWT proof.
        ///
        /// Returns the key the credential is to be bound to.
        pub async fn verify(
            &self,
            client_id: Option<&ClientId>,
            jwt: &str,
        ) -> Result<JWK, VerificationError> {
            let jws = Jws::new(jwt).map_err(|_| ProofValidationError::InvalidProof)?;

            let decoded = jws
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

            Ok(jwk.into_owned())
        }
    }

    pub async fn create_jwt_proof(
        issuer: Option<String>,
        audience: UriBuf,
        expire_in: Option<Duration>,
        nonce: Option<String>,
        signer: &impl JwsSigner,
    ) -> Result<JwsBuf, SignatureError> {
        let now = Utc::now();

        let body = JwtProofBody {
            issuer,
            audience,
            issued_at: now,
            not_before: None,
            expires_at: expire_in.map(|d| now + d),
            nonce,
        };

        body.sign(signer).await
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
        #[serde(rename = "iss")]
        pub issuer: Option<String>,

        /// Credential Issuer Identifier.
        #[serde(rename = "aud")]
        pub audience: UriBuf,

        /// Time at which the key proof was issued.
        #[serde(rename = "iat")]
        pub issued_at: DateTime<Utc>,

        /// Time from which the key proof may be verified.
        #[serde(rename = "nbf")]
        pub not_before: Option<DateTime<Utc>>,

        /// Proof expiration time.
        #[serde(rename = "exp")]
        pub expires_at: Option<DateTime<Utc>>,

        /// Server-provided `c_nonce` value.
        ///
        /// It *must* be present when the issuer has a Nonce Endpoint.
        #[serde(rename = "nonce")]
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

    impl ValidateCoseHeader<VerificationParams<'_>> for JwtProofBody {
        fn validate_cose_headers(
            &self,
            _params: &VerificationParams<'_>,
            _protected: &ssi::claims::cose::ProtectedHeader,
            _unprotected: &ssi::claims::cose::Header,
        ) -> ClaimsValidity {
            // if let Some(jwk) = &params.controller_jwk {
            //     if jwk != &self.controller.jwk {
            //         return Err(VerificationError::InvalidJWK);
            //     }
            // }

            // if let Some(did) = &params.controller_did {
            //     if self.controller.vm.is_none() {
            //         return Err(VerificationError::InvalidDID {
            //             expected: did.to_string(),
            //             actual: format!("{:?}", self.controller.vm),
            //         });
            //     }
            // }

            Ok(())
        }
    }

    impl<S> ValidateClaims<VerificationParams<'_>, S> for JwtProofBody {
        fn validate_claims(&self, params: &VerificationParams<'_>, _proof: &S) -> ClaimsValidity {
            let now = params.date_time();

            let time_tolerance = params.time_tolerance.unwrap_or_default();

            if let Some(not_before) = self.not_before {
                if (now + time_tolerance) < not_before {
                    return Err(InvalidClaims::Premature {
                        now,
                        valid_from: not_before,
                    });
                }
            }

            if let Some(expires_at) = self.expires_at {
                if (now - time_tolerance) > expires_at {
                    return Err(InvalidClaims::Expired {
                        now,
                        valid_until: expires_at,
                    });
                }
            }

            if self.issuer.as_deref() != params.client_id.map(|c| c.as_str()) {
                return Err(InvalidClaims::Other("Invalid issuer".to_owned()));
            }

            if self.audience != params.issuer {
                return Err(InvalidClaims::Other("Invalid audience".to_owned()));
            }

            Ok(())
        }
    }
}
