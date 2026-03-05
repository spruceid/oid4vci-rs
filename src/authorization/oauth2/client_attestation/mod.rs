//! OAuth 2.0 Attestation-Based Client Authentication.
//!
//! Extension to the OAuth 2 protocol which enables a Client Instance to include
//! a key-bound attestation in interactions with an Authorization Server or a
//! Resource Server.
//!
//! See: <https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html>
use std::{borrow::Cow, time::Duration};

use open_auth2::{
    http::{self, HeaderName},
    ClientId, ClientIdBuf,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use ssi::{
    claims::{
        chrono::Utc,
        cose::ValidateCoseHeader,
        jws::ValidateJwsHeader,
        jwt::{ClaimSet, ExpirationTime, IssuedAt, NotBefore},
        ClaimsValidity, DateTimeProvider, InvalidClaims, Jws, JwsBuf, JwsPayload, ResolverProvider,
        ValidateClaims,
    },
    JWK,
};

mod client;
mod server;

pub use client::*;
pub use server::*;

use crate::util::{jwt_iat_now, jwt_numeric_date};

/// Value of a Client Attestation JWT header's the `typ` claim.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#name-client-attestation-jwt>
pub const CLIENT_ATTESTATION_JWT_TYP: &str = "oauth-client-attestation+jwt";

/// Value of a Client Attestation PoP JWT header's the `typ` claim.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#name-client-attestation-pop-jwt>
pub const CLIENT_ATTESTATION_POP_JWT_TYP: &str = "oauth-client-attestation-pop+jwt";

/// Claims of a Client Attestation JWT.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#name-client-attestation-jwt>
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientAttestation {
    /// Issuer.
    pub iss: String,

    /// Subject, which *must* be the OAuth Client `client_id` value.
    pub sub: ClientIdBuf,

    /// Proof expiration time.
    pub exp: ExpirationTime,

    /// Public key used to generate the Client Attestation Pop JWT.
    pub cnf: ClientAttestationCnf,

    /// Time at which the key proof was issued.
    pub iat: Option<IssuedAt>,

    /// Time from which the key proof may be verified.
    pub nbf: Option<NotBefore>,
}

impl ClientAttestation {
    pub fn new(iss: String, sub: ClientIdBuf, expire_in: Duration, cnf: JWK) -> Self {
        Self {
            iss,
            sub,
            exp: ExpirationTime(jwt_numeric_date(Utc::now() + expire_in)),
            cnf: ClientAttestationCnf { jwk: cnf },
            iat: Some(jwt_iat_now()),
            nbf: None,
        }
    }
}

impl JwsPayload for ClientAttestation {
    fn typ(&self) -> Option<&str> {
        Some(CLIENT_ATTESTATION_JWT_TYP)
    }

    fn payload_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

impl ClaimSet for ClientAttestation {}

struct ClientAttestationVerificationParams<'a, K> {
    key_resolver: K,
    expected_iss: Option<&'a str>,
    client_id: &'a ClientId,
}

impl<K> ResolverProvider for ClientAttestationVerificationParams<'_, K> {
    type Resolver = K;

    fn resolver(&self) -> &Self::Resolver {
        &self.key_resolver
    }
}

impl<K> DateTimeProvider for ClientAttestationVerificationParams<'_, K> {
    fn date_time(&self) -> ssi::claims::chrono::DateTime<ssi::claims::chrono::Utc> {
        ssi::claims::chrono::Utc::now()
    }
}

impl<K> ValidateJwsHeader<ClientAttestationVerificationParams<'_, K>> for ClientAttestation {}

impl<K> ValidateCoseHeader<ClientAttestationVerificationParams<'_, K>> for ClientAttestation {
    fn validate_cose_headers(
        &self,
        _params: &ClientAttestationVerificationParams<'_, K>,
        _protected: &ssi::claims::cose::ProtectedHeader,
        _unprotected: &ssi::claims::cose::Header,
    ) -> ClaimsValidity {
        Ok(())
    }
}

impl<K, S> ValidateClaims<ClientAttestationVerificationParams<'_, K>, S> for ClientAttestation {
    fn validate_claims(
        &self,
        params: &ClientAttestationVerificationParams<'_, K>,
        _proof: &S,
    ) -> ClaimsValidity {
        let now = params.date_time();

        if let Some(iss) = params.expected_iss {
            if self.iss != iss {
                return Err(InvalidClaims::other("Untrusted client attestation"));
            }
        }

        if self.sub != *params.client_id {
            return Err(InvalidClaims::other("Invalid client attestation subject"));
        }

        self.exp.verify(now)?;

        if let Some(not_before) = self.nbf {
            not_before.verify(now)?;
        }

        Ok(())
    }
}

/// Client Attestation Confirmation Key.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ClientAttestationCnf {
    pub jwk: JWK,
}

/// Claims of a Client Attestation Pop JWT.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#name-client-attestation-pop-jwt>
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientAttestationPop {
    /// Issuer.
    pub iss: ClientIdBuf,

    /// Audience, which *must* be the Authorization Server's issuer identifier
    /// URL.
    pub aud: String,

    /// JWT identifier.
    ///
    /// The authorization server can utilize the `jti` value for replay attack
    /// detection.
    pub jti: String,

    /// Time at which the key proof was issued.
    pub iat: IssuedAt,

    /// Value provided by the Authorization Server to be included in this JWT.
    pub challenge: Option<String>,

    /// Time from which the key proof may be verified.
    pub nbf: Option<NotBefore>,
}

impl ClientAttestationPop {
    pub fn new(iss: ClientIdBuf, aud: String, jti: String, challenge: Option<String>) -> Self {
        Self {
            iss,
            aud,
            jti,
            iat: jwt_iat_now(),
            challenge,
            nbf: None,
        }
    }
}

impl JwsPayload for ClientAttestationPop {
    fn typ(&self) -> Option<&str> {
        Some(CLIENT_ATTESTATION_POP_JWT_TYP)
    }

    fn payload_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(serde_json::to_vec(self).unwrap())
    }
}

impl ClaimSet for ClientAttestationPop {}

struct ClientAttestationPopVerificationParams<'a> {
    pub client_attestation: &'a ClientAttestation,
    pub expected_aud: &'a str,
    pub challenge: Option<&'a str>,
}

impl ResolverProvider for ClientAttestationPopVerificationParams<'_> {
    type Resolver = JWK;

    fn resolver(&self) -> &Self::Resolver {
        &self.client_attestation.cnf.jwk
    }
}

impl DateTimeProvider for ClientAttestationPopVerificationParams<'_> {
    fn date_time(&self) -> ssi::claims::chrono::DateTime<ssi::claims::chrono::Utc> {
        ssi::claims::chrono::Utc::now()
    }
}

impl ValidateJwsHeader<ClientAttestationPopVerificationParams<'_>> for ClientAttestationPop {}

impl<S> ValidateClaims<ClientAttestationPopVerificationParams<'_>, S> for ClientAttestationPop {
    fn validate_claims(
        &self,
        params: &ClientAttestationPopVerificationParams<'_>,
        _proof: &S,
    ) -> ClaimsValidity {
        let now = params.date_time();

        if self.iss != params.client_attestation.sub {
            return Err(InvalidClaims::other(
                "PoP issuer doesn't match attestation subject",
            ));
        }

        if self.aud != params.expected_aud {
            return Err(InvalidClaims::other("Wrong PoP audience"));
        }

        self.iat.verify(now)?;

        if params.challenge != self.challenge.as_deref() {
            return Err(InvalidClaims::other("PoP challenge failed"));
        }

        if let Some(not_before) = self.nbf {
            not_before.verify(now)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ClientAttestationAndPop {
    pub client_attestation: JwsBuf,
    pub client_attestation_pop: JwsBuf,
}

impl ClientAttestationAndPop {
    pub fn as_ref(&self) -> ClientAttestationAndPopRef<'_> {
        ClientAttestationAndPopRef {
            client_attestation: &self.client_attestation,
            client_attestation_pop: &self.client_attestation_pop,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ClientAttestationAndPopRef<'a> {
    pub client_attestation: &'a Jws,
    pub client_attestation_pop: &'a Jws,
}

impl<'a> From<&'a ClientAttestationAndPop> for ClientAttestationAndPopRef<'a> {
    fn from(value: &'a ClientAttestationAndPop) -> Self {
        value.as_ref()
    }
}

/// `OAuth-Client-Attestation` HTTP header.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#name-client-attestation-http-hea>
pub const OAUTH_CLIENT_ATTESTATION: HeaderName =
    HeaderName::from_static("oauth-client-attestation");

/// `OAuth-Client-Attestation-PoP` HTTP header.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html#name-client-attestation-http-hea>
pub const OAUTH_CLIENT_ATTESTATION_POP: HeaderName =
    HeaderName::from_static("oauth-client-attestation-pop");

pub trait HttpRequestWithOAuthClientAttestation: Sized {
    fn insert_oauth_client_attestation(&mut self, attestation_and_pop: ClientAttestationAndPopRef);

    fn insert_oauth_client_attestation_opt(
        &mut self,
        attestation_and_pop: Option<ClientAttestationAndPopRef>,
    ) {
        if let Some(attestation_and_pop) = attestation_and_pop {
            self.insert_oauth_client_attestation(attestation_and_pop)
        }
    }
}

impl<B> HttpRequestWithOAuthClientAttestation for http::Request<B> {
    fn insert_oauth_client_attestation(&mut self, attestation_and_pop: ClientAttestationAndPopRef) {
        self.headers_mut().insert(
            OAUTH_CLIENT_ATTESTATION,
            attestation_and_pop
                .client_attestation
                .as_str()
                .try_into()
                .unwrap(),
        );
        self.headers_mut().insert(
            OAUTH_CLIENT_ATTESTATION_POP,
            attestation_and_pop
                .client_attestation_pop
                .as_str()
                .try_into()
                .unwrap(),
        );
    }
}

pub trait ValidateOAuthClientAttestation {
    fn validate_oauth_client_attestation(&self);
}

impl<B> ValidateOAuthClientAttestation for http::Response<B> {
    fn validate_oauth_client_attestation(&self) {
        todo!()
    }
}
