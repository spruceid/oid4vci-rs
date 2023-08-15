use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use ssi::{
    did::{Resource, VerificationMethod},
    did_resolve::{dereference, Content, DIDResolver, DereferencingInputMetadata},
    jwk::{Algorithm, JWK},
    jws::{self, Header},
    jwt,
    vc::VCDateTime,
};
use url::Url;

use crate::{nonce::generate_nonce, CredentialRequestErrorType, OIDCError, Proof, Timestamp};

const JWS_TYPE: &str = "openid4vci-proof+jwt";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofOfPossessionBody {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: Url,
    #[serde(rename = "nbf")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<Timestamp>,
    #[serde(rename = "iat")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<Timestamp>,
    #[serde(rename = "exp")]
    pub expires_at: Timestamp,
    #[serde(rename = "jti")]
    pub nonce: String,
}

#[derive(Debug, Clone)]
pub struct ProofOfPossession {
    pub body: ProofOfPossessionBody,
    pub controller: ProofOfPossessionController,
}

#[derive(Debug, Clone)]
pub struct ProofOfPossessionController {
    pub vm: Option<String>,
    pub jwk: JWK,
}

pub struct ProofOfPossessionParams {
    pub audience: Url,
    pub issuer: String,
    pub nonce: Option<String>,
    pub controller: ProofOfPossessionController,
}

pub struct ProofOfPossessionVerificationParams {
    pub audience: Url,
    pub issuer: String,
    pub nonce: String,
    pub controller_did: Option<String>,
    pub controller_jwk: Option<JWK>,
    /// Slack in nbf validation to deal with clock synchronisation issues.
    pub nbf_tolerance: Option<Duration>,
    /// Slack in exp validation to deal with clock synchronisation issues.
    pub exp_tolerance: Option<Duration>,
}

impl ProofOfPossession {
    pub fn generate(params: &ProofOfPossessionParams, expiry: Duration) -> Result<Self, OIDCError> {
        let now = VCDateTime::from(Utc::now());
        let exp = VCDateTime::from(Utc::now() + expiry);
        Ok(Self {
            body: ProofOfPossessionBody {
                issuer: params.issuer.clone(),
                audience: params.audience.clone(),
                not_before: Some(now.clone().into()),
                issued_at: Some(now.into()),
                expires_at: exp.into(),
                nonce: params.nonce.clone().unwrap_or_else(generate_nonce),
            },
            controller: params.controller.clone(),
        })
    }

    pub fn to_jwt(&self) -> Result<String, OIDCError> {
        let jwk = &self.controller.jwk;
        let alg = if let Some(a) = jwk.get_algorithm() {
            a
        } else {
            return Err(OIDCError::default()
                .with_desc("Unable to select JWT algorithm, please specify in JWK."));
        };
        let payload = serde_json::to_string(&self.body)?;
        let (h_kid, h_jwk) = match (self.controller.vm.clone(), jwk.key_id.clone()) {
            (Some(did), _) => (Some(did), None),
            (None, Some(kid)) => (Some(kid), None),
            (None, None) => (None, Some(jwk.to_public())),
        };
        let header = Header {
            algorithm: alg,
            key_id: h_kid,
            jwk: h_jwk,
            type_: Some(JWS_TYPE.to_string()),
            ..Default::default()
        };
        jws::encode_sign_custom_header(&payload, jwk, &header).map_err(|e| e.into())
    }

    pub async fn from_proof(proof: &Proof, resolver: &dyn DIDResolver) -> Result<Self, OIDCError> {
        match proof {
            Proof::JWT { jwt } => Self::from_jwt(jwt, resolver).await,
        }
    }

    pub async fn from_jwt(jwt: &str, resolver: &dyn DIDResolver) -> Result<Self, OIDCError> {
        let header: Header = jws::decode_unverified(jwt)?.0;

        if header.type_ != Some(JWS_TYPE.to_string()) {
            let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
            return Err(err.with_desc(&format!("invalid JWS header type, must be {JWS_TYPE}")));
        }
        if header.algorithm == Algorithm::None {
            let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
            return Err(err.with_desc("algorithm cannot be none"));
        }
        let (controller, jwk) = match (header.key_id, header.jwk, header.x509_certificate_chain) {
            (Some(kid), None, None) => get_jwk_from_kid(&kid, resolver)
                .await
                .map(|r| (Some(r.0), r.1))?,
            (None, Some(jwk), None) => (None, jwk),
            (None, None, Some(_x5c)) => {
                unimplemented!();
            }
            _ => {
                let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
                return Err(err.with_desc(
                    "exactly one of the following parameters needs to be present: (kid, jwk, x5c)",
                ));
            }
        };
        let body = jwt::decode_verify(jwt, &jwk)?;
        Ok(Self {
            body,
            controller: ProofOfPossessionController {
                vm: controller,
                jwk,
            },
        })
    }

    pub async fn verify(
        &self,
        params: &ProofOfPossessionVerificationParams,
    ) -> Result<(), OIDCError> {
        let now = Utc::now();

        let nbf_tolerance = params.nbf_tolerance.unwrap_or_else(Duration::zero);
        let exp_tolerance = params.exp_tolerance.unwrap_or_else(Duration::zero);

        if let Some(not_before) = self.body.not_before.clone() {
            let nbf = not_before.try_into()?;
            if (now + nbf_tolerance) < nbf {
                let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
                return Err(err.with_desc("proof of possession is not yet valid"));
            }
        }

        let exp = self.body.expires_at.clone().try_into()?;
        if (now - exp_tolerance) > exp {
            let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
            return Err(err.with_desc("proof of possession has expired"));
        }

        if self.body.issuer != params.issuer {
            let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
            return Err(err.with_desc(&format!(
                "issuer does not match, must be '{}'",
                params.issuer
            )));
        }

        let expected_audience = &params.audience;
        if self.body.audience != *expected_audience {
            let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
            return Err(err.with_desc(&format!(
                "audience does not match, must be '{expected_audience}'"
            )));
        }

        if let Some(jwk) = &params.controller_jwk {
            if jwk != &self.controller.jwk {
                let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
                return Err(err.with_desc("JWK does not match"));
            }
        }
        if let Some(did) = &params.controller_did {
            if Some(did) != self.controller.vm.as_ref() {
                let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
                return Err(err.with_desc(&format!("DID does not match, must be {did}")));
            }
        }

        Ok(())
    }
}

async fn get_jwk_from_kid(
    kid: &str,
    resolver: &dyn DIDResolver,
) -> Result<(String, JWK), OIDCError> {
    let (_, content, _) = dereference(resolver, kid, &DereferencingInputMetadata::default()).await;

    let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
    let vm = match content {
        Content::Object(Resource::VerificationMethod(vm)) => Ok(vm),
        Content::DIDDocument(document) => {
            if let VerificationMethod::Map(vm) =
                document.verification_method.unwrap().first().unwrap()
            {
                Ok(vm.to_owned())
            } else {
                Err(err.with_desc("could not find any verification method"))
            }
        }

        _ => Err(err.with_desc("could not find specified verification method")),
    }?;

    Ok((
        vm.controller.clone(),
        vm.get_jwk()
            .map_err(|_| CredentialRequestErrorType::InvalidOrMissingProof.into())
            .map_err(|e: OIDCError| e.with_desc("verification method does not contain a jwk"))?,
    ))
}

#[cfg(test)]
mod test {
    use chrono::{DateTime, FixedOffset};
    use did_jwk::DIDJWK;
    use serde_json::json;
    use ssi::did::{DIDMethod, Source};

    use super::*;

    #[tokio::test]
    async fn basic() {
        let jwk = serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","x":"h3GzIK3pU8oTspVBKstiPSHR3VH_USS2FA0NrAOZ51s","d":"pfYMFvJ-LlMO4-EBBsrjpfAVz5UEYNVgbTphLPZypbE"})).unwrap();
        let did = DIDJWK.generate(&Source::Key(&jwk)).unwrap();

        let pop = ProofOfPossession::generate(
            &ProofOfPossessionParams {
                issuer: "test".to_string(),
                audience: Url::parse("http://localhost:300").unwrap(),
                nonce: None,
                controller: ProofOfPossessionController {
                    jwk,
                    vm: Some(did.clone()),
                },
            },
            Duration::minutes(5),
        )
        .unwrap()
        .to_jwt()
        .unwrap();

        let pop = ProofOfPossession::from_jwt(&pop, &DIDJWK).await.unwrap();
        pop.verify(&ProofOfPossessionVerificationParams {
            nonce: pop.body.nonce.clone(),
            audience: pop.body.audience.clone(),
            issuer: "test".to_string(),
            controller_did: Some(did),
            controller_jwk: None,
            nbf_tolerance: None,
            exp_tolerance: None,
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn nbf_tolerance() {
        let jwk = serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","x":"h3GzIK3pU8oTspVBKstiPSHR3VH_USS2FA0NrAOZ51s","d":"pfYMFvJ-LlMO4-EBBsrjpfAVz5UEYNVgbTphLPZypbE"})).unwrap();
        let did = DIDJWK.generate(&Source::Key(&jwk)).unwrap();

        let mut pop = ProofOfPossession::generate(
            &ProofOfPossessionParams {
                issuer: "test".to_string(),
                audience: Url::parse("http://localhost:300").unwrap(),
                nonce: None,
                controller: ProofOfPossessionController {
                    jwk,
                    vm: Some(did.clone()),
                },
            },
            Duration::minutes(5),
        )
        .unwrap();

        let nbf = pop
            .body
            .not_before
            .as_ref()
            .map(|nbf| nbf.clone().try_into())
            .transpose()
            .unwrap()
            .map(|nbf: DateTime<FixedOffset>| nbf + Duration::minutes(5))
            .map(VCDateTime::from)
            .map(Timestamp::from);

        pop.body.not_before = nbf;

        let pop_jwt = pop.to_jwt().unwrap();
        let pop = ProofOfPossession::from_jwt(&pop_jwt, &DIDJWK)
            .await
            .unwrap();

        let mut verification_params = ProofOfPossessionVerificationParams {
            nonce: pop.body.nonce.clone(),
            audience: pop.body.audience.clone(),
            issuer: "test".to_string(),
            controller_did: Some(did),
            controller_jwk: None,
            nbf_tolerance: None,
            exp_tolerance: None,
        };

        pop.verify(&verification_params)
            .await
            .expect_err("should have failed due to nbf");

        verification_params.nbf_tolerance = Some(Duration::minutes(5));

        pop.verify(&verification_params)
            .await
            .expect("should have passed with nbf tolerance");
    }

    #[tokio::test]
    async fn exp_tolerance() {
        let jwk = serde_json::from_value(json!({"kty":"OKP","crv":"Ed25519","x":"h3GzIK3pU8oTspVBKstiPSHR3VH_USS2FA0NrAOZ51s","d":"pfYMFvJ-LlMO4-EBBsrjpfAVz5UEYNVgbTphLPZypbE"})).unwrap();
        let did = DIDJWK.generate(&Source::Key(&jwk)).unwrap();

        let pop = ProofOfPossession::generate(
            &ProofOfPossessionParams {
                issuer: "test".to_string(),
                audience: Url::parse("http://localhost:300").unwrap(),
                nonce: None,
                controller: ProofOfPossessionController {
                    jwk,
                    vm: Some(did.clone()),
                },
            },
            Duration::zero(),
        )
        .unwrap();

        let pop_jwt = pop.to_jwt().unwrap();
        let pop = ProofOfPossession::from_jwt(&pop_jwt, &DIDJWK)
            .await
            .unwrap();

        let mut verification_params = ProofOfPossessionVerificationParams {
            nonce: pop.body.nonce.clone(),
            audience: pop.body.audience.clone(),
            issuer: "test".to_string(),
            controller_did: Some(did),
            controller_jwk: None,
            nbf_tolerance: None,
            exp_tolerance: None,
        };

        pop.verify(&verification_params)
            .await
            .expect_err("should have failed due to exp");

        verification_params.exp_tolerance = Some(Duration::minutes(5));

        pop.verify(&verification_params)
            .await
            .expect("should have passed with exp tolerance");
    }
}
