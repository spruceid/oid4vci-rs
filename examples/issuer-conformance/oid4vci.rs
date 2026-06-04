use std::{borrow::Cow, sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::{header::AUTHORIZATION, HeaderMap},
};
use base64::Engine as _;
use dashmap::DashMap;
use iref::UriBuf;
use oid4vci::{
    authorization::oauth2::dpop::{verify_dpop_proof, DPOP},
    credential::CredentialOrConfigurationId,
    endpoints::credential::{CredentialResponse, ImmediateCredentialResponse},
    offer::{
        CredentialOfferGrants, CredentialOfferParameters, PreAuthorizedCodeGrant, TxCodeDefinition,
    },
    profile::{
        ProfileCredentialIssuerMetadata, ProfileCredentialRequest, ProfileCredentialResponse,
    },
    proof::{jwt::JwtProofVerifier, Proofs},
    server::{CredentialErrorCode, Oid4vciServer, ServerError},
    CredentialOffer, Oid4vciCredential, StandardProfile,
};
use open_auth2::AccessTokenBuf;
use rand::distr::{Alphanumeric, SampleString};
use sha2::{Digest, Sha256};
use ssi::{
    claims::jws::Jws,
    dids::{AnyDidMethod, VerificationMethodDIDResolver},
    prelude::AnyMethod,
};
use time::UtcDateTime;

use crate::{oauth2::PreAuthorizedCodeMetadata, Error, Server};

/// Lifetime of a `c_nonce` issued by the Nonce Endpoint.
const NONCE_TTL: Duration = Duration::from_secs(300);

/// Maximum accepted age of a DPoP proof's `iat` at the resource server.
const DPOP_PROOF_MAX_AGE: Duration = Duration::from_secs(300);

#[derive(Default)]
pub struct Oid4vciState {
    credential_offers: DashMap<String, CredentialOfferParameters>,

    /// Nonces handed out by the Nonce Endpoint, with their expiry. A `c_nonce`
    /// is valid until it expires and is consumed on first use (single-use), so
    /// a replayed or unknown nonce is rejected (OpenID4VCI §8.2.3).
    nonces: DashMap<String, UtcDateTime>,

    /// `jti` values of accepted DPoP proofs, with their expiry, for replay
    /// detection (RFC 9449 §11.1). Entries are kept for the proof validity
    /// window and dropped once expired.
    dpop_jtis: DashMap<String, UtcDateTime>,
}

impl Server {
    /// Validates the DPoP proof presented with a DPoP-bound access token at the
    /// resource server (RFC 9449 §7.1): the request must use the `DPoP`
    /// authorization scheme and carry a `DPoP` proof valid for this request
    /// (`POST` to the Credential Endpoint, recent `iat`), signed by the key the
    /// access token is bound to (`jkt`), with an `ath` equal to the access token
    /// hash.
    async fn validate_dpop(
        &self,
        headers: &HeaderMap,
        access_token: &AccessTokenBuf,
        expected_jkt: &str,
    ) -> Result<(), String> {
        let scheme = headers
            .get(&AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once(' '))
            .map(|(scheme, _)| scheme);
        if !matches!(scheme, Some(s) if s.eq_ignore_ascii_case("dpop")) {
            return Err("access token not presented with the DPoP scheme".to_owned());
        }

        // RFC 9449 §4.3: there must be exactly one DPoP proof header.
        if headers.get_all(&DPOP).iter().count() != 1 {
            return Err("expected exactly one DPoP proof header".to_owned());
        }

        let dpop = headers
            .get(&DPOP)
            .and_then(|v| v.to_str().ok())
            .ok_or("missing DPoP proof header")?;
        let dpop = Jws::new(dpop).map_err(|_| "malformed DPoP proof")?;

        let htu = self.config.credential_endpoint();
        let verified = verify_dpop_proof(dpop, "POST", &htu, DPOP_PROOF_MAX_AGE)
            .await
            .map_err(|e| e.to_string())?;

        // RFC 9449 §4.3: the `jwk` header must be a public key.
        if !verified.jwk.is_public() {
            return Err("DPoP proof `jwk` header contains private key material".to_owned());
        }

        // The proof key must be the one the access token is bound to.
        let jkt = verified.jwk.thumbprint().map_err(|e| e.to_string())?;
        if jkt != expected_jkt {
            return Err(format!(
                "DPoP proof key thumbprint `{jkt}` does not match the token binding `{expected_jkt}`"
            ));
        }

        // RFC 9449 §4.3: `ath` is the base64url SHA-256 of the access token.
        let expected_ath = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(access_token.as_bytes()));
        if verified.proof.ath.as_deref() != Some(expected_ath.as_str()) {
            return Err("DPoP proof `ath` does not match the access token".to_owned());
        }

        // RFC 9449 §11.1: detect replay by `jti` within the proof validity
        // window. Reject a `jti` already seen; otherwise remember this one. Drop
        // expired entries opportunistically to keep the set bounded.
        let now = UtcDateTime::now();
        self.oid4vci.dpop_jtis.retain(|_, expiry| *expiry >= now);
        if self
            .oid4vci
            .dpop_jtis
            .insert(verified.proof.jti.clone(), now + DPOP_PROOF_MAX_AGE)
            .is_some()
        {
            return Err("DPoP proof `jti` has already been used".to_owned());
        }

        Ok(())
    }

    /// Validates the `c_nonce` carried by a key proof and consumes it.
    ///
    /// A missing nonce is an `invalid_proof`; an unknown, expired, or already
    /// used nonce is an `invalid_nonce` (OpenID4VCI §8.3.1.2). Consuming on use
    /// makes nonces single-use, rejecting replays.
    fn consume_nonce(&self, nonce: Option<&str>) -> Result<(), ServerError> {
        let nonce = nonce.ok_or_else(|| {
            log::warn!("credential request: key proof is missing the c_nonce");
            ServerError::CredentialRequest(
                CredentialErrorCode::InvalidProof,
                Some("key proof is missing the c_nonce".to_owned()),
            )
        })?;

        match self.oid4vci.nonces.remove(nonce) {
            Some((_, expiry)) if expiry >= UtcDateTime::now() => Ok(()),
            _ => {
                log::warn!("credential request: c_nonce is unknown, expired, or already used");
                Err(ServerError::CredentialRequest(
                    CredentialErrorCode::InvalidNonce,
                    Some("the c_nonce is invalid or expired".to_owned()),
                ))
            }
        }
    }
}

impl Oid4vciServer for Server {
    type Profile = StandardProfile;

    async fn metadata(
        &self,
    ) -> Result<Cow<'_, ProfileCredentialIssuerMetadata<Self::Profile>>, ServerError> {
        Ok(Cow::Owned(self.config.credential_issuer_metadata()))
    }

    async fn nonce(&self) -> Result<String, ServerError> {
        // Generate a fresh `c_nonce` and remember it so the Credential Endpoint
        // can later verify the proof was bound to a nonce we issued.
        let nonce = Alphanumeric.sample_string(&mut rand::rng(), 32);
        self.oid4vci
            .nonces
            .insert(nonce.clone(), UtcDateTime::now() + NONCE_TTL);
        Ok(nonce)
    }

    async fn credential(
        &self,
        headers: HeaderMap,
        access_token: AccessTokenBuf,
        request: ProfileCredentialRequest<Self::Profile>,
    ) -> Result<ProfileCredentialResponse<Self::Profile>, ServerError> {
        log::debug!("credential request: {request:#?}");

        let m = self
            .oauth2
            .access_token_metadata(&access_token)
            .ok_or_else(|| {
                log::warn!("credential request: unknown access token");
                ServerError::Unauthorized("unknown access token".into())
            })?;

        // When the access token is DPoP-bound, the resource server MUST validate
        // the accompanying DPoP proof (RFC 9449 §7.1).
        if let Some(expected_jkt) = &m.jkt {
            self.validate_dpop(&headers, &access_token, expected_jkt)
                .await
                .map_err(|e| {
                    log::warn!("credential request: DPoP validation failed: {e}");
                    ServerError::Unauthorized(format!("DPoP proof validation failed: {e}").into())
                })?;
        }

        let (config, value) = match request.credential {
            CredentialOrConfigurationId::Credential(id) => {
                self.config.get_credential(&id).ok_or_else(|| {
                    log::warn!("credential request: unknown credential identifier {id:?}");
                    ServerError::CredentialRequest(
                        CredentialErrorCode::UnknownCredentialIdentifier,
                        None,
                    )
                })?
            }
            CredentialOrConfigurationId::Configuration(id) => {
                let config = self
                    .config
                    .credential_configurations
                    .get(&id)
                    .ok_or_else(|| {
                        log::warn!("credential request: unknown credential configuration {id:?}");
                        ServerError::CredentialRequest(
                            CredentialErrorCode::UnknownCredentialConfiguration,
                            None,
                        )
                    })?;
                let mut credentials = config.credentials.iter();
                let (_, value) = credentials.next().ok_or(ServerError::Unauthorized(
                    "credential configuration has no credentials".into(),
                ))?;
                if credentials.next().is_some() {
                    return Err(ServerError::Unauthorized(
                        "credential configuration has more than one credential".into(),
                    ));
                }

                (config, value)
            }
        };

        let issuer = self.config.credential_issuer();

        let credentials = match &request.proofs {
            Some(proofs) => {
                let verified = match proofs {
                    Proofs::Jwt(jwts) => {
                        let jwk_resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(
                            AnyDidMethod::default(),
                        );
                        let verifier = JwtProofVerifier::new(&issuer, &jwk_resolver);

                        verifier
                            .verify_list(m.client_id.as_deref(), jwts)
                            .await
                            .map_err(|e| {
                                log::warn!("credential request: proof verification failed: {e}");
                                ServerError::CredentialRequest(
                                    CredentialErrorCode::InvalidProof,
                                    None,
                                )
                            })?
                    }
                    _ => todo!(),
                };

                let mut credentials = Vec::with_capacity(verified.len());

                for proof in verified {
                    // The proof MUST be bound to a fresh, server-issued nonce
                    // (OpenID4VCI §8.2.3); reject missing/invalid/replayed ones.
                    self.consume_nonce(proof.nonce.as_deref())?;

                    credentials.push(Oid4vciCredential::new(
                        config
                            .sign(
                                issuer.as_str(),
                                &self.jwk,
                                m.client_id.as_deref(),
                                value,
                                Some(&proof.key),
                            )
                            .await,
                    ));
                }

                credentials
            }
            None => {
                // Every credential configuration here advertises
                // `proof_types_supported`, so a key proof is REQUIRED
                // (OpenID4VCI §8.2). A request without `proofs` is an
                // `invalid_proof` error (§8.3.1.2).
                log::warn!("credential request: missing required proofs");
                return Err(ServerError::CredentialRequest(
                    CredentialErrorCode::InvalidProof,
                    Some("the credential configuration requires a key proof".to_owned()),
                ));
            }
        };

        Ok(CredentialResponse::Immediate(
            ImmediateCredentialResponse::new(credentials),
        ))
    }
}

pub async fn credential_offer(
    State(server): State<Arc<Server>>,
    Path(credential_offer_id): Path<String>,
) -> Result<CredentialOfferParameters, Error> {
    let params = server
        .oid4vci
        .credential_offers
        .get(&credential_offer_id)
        .ok_or(Error::UnknownCredentialOffer)?;

    Ok(params.clone())
}

pub async fn new_credential_offer(State(server): State<Arc<Server>>) -> String {
    let grants = if server.config.pre_auth {
        let pa_code = server
            .oauth2
            .new_pre_authorized_code(PreAuthorizedCodeMetadata {
                tx_code: server.config.tx_code.clone(),
            });

        let mut grant = PreAuthorizedCodeGrant::new(pa_code);

        if server.config.tx_code.is_some() {
            grant.tx_code = Some(TxCodeDefinition::default())
        }

        CredentialOfferGrants {
            pre_authorized_code: Some(grant),
            ..Default::default()
        }
    } else {
        CredentialOfferGrants {
            authorization_code: Some(Default::default()),
            ..Default::default()
        }
    };

    let base_url = server.config.credential_issuer();
    let params = CredentialOfferParameters {
        credential_issuer: base_url.clone(),
        credential_configuration_ids: server
            .config
            .credential_configurations
            .keys()
            .cloned()
            .collect(),
        grants,
    };

    let credential_offer = if server.config.by_ref {
        let id = Alphanumeric.sample_string(&mut rand::rng(), 30);
        server.oid4vci.credential_offers.insert(id.clone(), params);
        let uri = UriBuf::new(format!("{base_url}/offer/{id}").into_bytes()).unwrap();
        CredentialOffer::Reference(uri)
    } else {
        CredentialOffer::Value(params)
    };

    credential_offer.to_uri().into_string()
}
