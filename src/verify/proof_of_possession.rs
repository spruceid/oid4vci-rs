use chrono::prelude::*;
use did_method_jwk::*;
use did_method_key::*;
use lazy_static::lazy_static;
use ssi::{
    did::{DIDMethods, Resource},
    did_resolve::{dereference, Content, DereferencingInputMetadata},
    jws::{decode_unverified, Header},
};

use crate::{
    codec::*,
    error::{CredentialRequestErrorType, OIDCError},
    jose::*,
    Metadata, Proof, ProofOfPossession,
};

lazy_static! {
    static ref DID_METHODS: DIDMethods<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(&DIDKey);
        methods.insert(&DIDJWK);
        methods
    };
}

pub async fn verify_proof_of_possession<M>(proof: &Proof, metadata: &M) -> Result<String, OIDCError>
where
    M: Metadata,
{
    match proof {
        Proof::JWT { jwt, .. } => {
            let header: Header = decode_unverified(jwt)?.0;
            let did_url = header
                .key_id
                .ok_or(CredentialRequestErrorType::InvalidOrMissingProof)?;

            let (controller, jwk) = {
                let content = dereference(
                    DID_METHODS.to_resolver(),
                    &did_url,
                    &DereferencingInputMetadata::default(),
                )
                .await
                .1;

                let resource = if let Content::Object(resource) = content {
                    Ok(resource)
                } else {
                    Err(CredentialRequestErrorType::InvalidOrMissingProof)
                }?;

                let vm = if let Resource::VerificationMethod(vm) = resource {
                    Ok(vm)
                } else {
                    Err(CredentialRequestErrorType::InvalidOrMissingProof)
                }?;

                (
                    vm.controller.clone(),
                    vm.get_jwk()
                        .map_err(|_| CredentialRequestErrorType::InvalidOrMissingProof)?,
                )
            };

            let interface = SSI::new(jwk, header.algorithm);

            let ProofOfPossession {
                // issuer,
                audience,
                issued_at,
                expires_at,
                ..
            } = {
                let (_, bytes) = interface.jwt_decode_verify(jwt)?;
                serde_json::from_slice(&bytes)?
            };

            let now = Utc::now();

            // Verification time is not before `iat`
            let iat = ToDateTime::from_vcdatetime(issued_at)?;
            if now < iat {
                return Err(CredentialRequestErrorType::InvalidOrMissingProof.into());
            }

            // Verification time is not after `exp`
            let exp = ToDateTime::from_vcdatetime(expires_at)?;
            if now > exp {
                return Err(CredentialRequestErrorType::InvalidOrMissingProof.into());
            }

            // TODO: match issuer to something
            // if issuer != "something" {
            //     return Err(CredentialRequestErrorType::InvalidOrMissingProof.into());
            // }

            // Audience is set to what is provided by Metadata
            if audience != metadata.get_audience() {
                return Err(CredentialRequestErrorType::InvalidOrMissingProof.into());
            }

            Ok(controller)
        }
    }
}
