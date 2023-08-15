use did_jwk::*;
use did_method_key::*;
use did_web::*;
use lazy_static::lazy_static;
use ssi::{
    did::{DIDMethod, DIDMethods, Source},
    vc::{get_verification_methods_for_purpose, ProofPurpose},
};
use url::Url;

use crate::{
    error::OIDCError, Metadata, Proof, ProofOfPossession, ProofOfPossessionVerificationParams,
};

lazy_static! {
    static ref DID_METHODS: DIDMethods<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(Box::new(DIDKey));
        methods.insert(Box::new(DIDJWK));
        methods.insert(Box::new(DIDWeb));
        methods
    };
}

#[deprecated = "Use ProofOfPossession::verify"]
pub async fn verify_proof_of_possession<M>(proof: &Proof, metadata: &M) -> Result<String, OIDCError>
where
    M: Metadata,
{
    match proof {
        Proof::JWT { jwt, .. } => {
            let pop = ProofOfPossession::from_jwt(jwt, DID_METHODS.to_resolver()).await?;
            pop.verify(&ProofOfPossessionVerificationParams {
                audience: Url::parse(metadata.get_audience()).unwrap(),
                issuer: pop.body.issuer.clone(),
                nonce: pop.body.nonce.clone(),
                controller_did: None,
                controller_jwk: None,
                exp_tolerance: None,
                nbf_tolerance: None,
            })
            .await?;

            let issuer = DIDJWK.generate(&Source::Key(&pop.controller.jwk)).unwrap();
            let verification_method = get_verification_methods_for_purpose(
                &issuer,
                &DIDJWK,
                ProofPurpose::AssertionMethod,
            )
            .await
            .unwrap()
            .first()
            .unwrap()
            .to_owned();
            Ok(verification_method)
        }
    }
}
