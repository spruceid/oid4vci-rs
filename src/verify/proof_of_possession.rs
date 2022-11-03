use chrono::prelude::*;
use did_jwk::*;
use did_method_key::*;
use did_web::*;
use lazy_static::lazy_static;
use ssi::{
    did::{DIDMethods, Resource, Source, VerificationMethod},
    did_resolve::{dereference, Content, DereferencingInputMetadata},
    jws::{decode_unverified, Header},
    vc::{get_verification_methods_for_purpose, ProofPurpose},
};

use crate::{
    error::{CredentialRequestErrorType, OIDCError},
    jose::*,
    Metadata, Proof, ProofOfPossession,
};

lazy_static! {
    static ref DID_METHODS: DIDMethods<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(&DIDKey);
        methods.insert(&DIDJWK);
        methods.insert(&DIDWeb);
        methods
    };
}

async fn get_jwk(header: &Header) -> Result<(String, ssi::jwk::JWK), OIDCError> {
    if header.key_id.is_some() {
        let did_url = header.key_id.to_owned().unwrap();
        let content = dereference(
            DID_METHODS.to_resolver(),
            &did_url,
            &DereferencingInputMetadata::default(),
        )
        .await
        .1;

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

            _ => Err(err.with_desc("could not find specified verirication method")),
        }?;

        Ok((
            vm.controller.clone(),
            vm.get_jwk()
                .map_err(|_| CredentialRequestErrorType::InvalidOrMissingProof.into())
                .map_err(|e: OIDCError| {
                    e.with_desc("verification method does not contain a jwk")
                })?,
        ))
    } else if header.jwk.is_some() {
        let jwk = header.jwk.to_owned().unwrap();

        let did_method = DID_METHODS.get("jwk").unwrap();
        let did_resolver = did_method.to_resolver();
        let issuer = did_method.generate(&Source::Key(&jwk)).unwrap();
        let verification_method = get_verification_methods_for_purpose(
            &issuer,
            did_resolver,
            ProofPurpose::AssertionMethod,
        )
        .await
        .unwrap()
        .first()
        .unwrap()
        .to_owned();

        Ok((verification_method, jwk))
    } else {
        let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
        Err(err.with_desc("jwt header must contain either `key_id` or `jwk`"))
    }
}

pub async fn verify_proof_of_possession<M>(proof: &Proof, metadata: &M) -> Result<String, OIDCError>
where
    M: Metadata,
{
    match proof {
        Proof::JWT { jwt, .. } => {
            let header: Header = decode_unverified(jwt)?.0;
            let (controller, jwk) = get_jwk(&header).await?;

            let interface = SSI::new(jwk, header.algorithm, "");

            let ProofOfPossession {
                // issuer,
                audience,
                not_before,
                expires_at,
                ..
            } = {
                let (_, bytes) = interface.jwt_decode_verify(jwt)?;
                serde_json::from_slice(&bytes)?
            };

            let now = Utc::now();

            // Verification time is not before `nbf`
            if let Some(not_before) = not_before {
                let nbf = not_before.try_into()?;
                if now < nbf {
                    let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
                    return Err(err.with_desc("proof of possesion is not yet valid"));
                }
            }

            // Verification time is not after `exp`
            let exp = expires_at.try_into()?;
            if now > exp {
                let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
                return Err(err.with_desc("proof of possesion is expired"));
            }

            // TODO: match issuer to something
            // if issuer != "something" {
            //     return Err(CredentialRequestErrorType::InvalidOrMissingProof.into());
            // }

            // Audience is set to what is provided by Metadata
            let expected_audience = metadata.get_audience();
            if audience != expected_audience {
                let err: OIDCError = CredentialRequestErrorType::InvalidOrMissingProof.into();
                return Err(err.with_desc(&format!(
                    "audience does not match this issuer, must be '{}'",
                    expected_audience
                )));
            }

            Ok(controller)
        }
    }
}
