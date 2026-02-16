use std::{borrow::Cow, sync::Arc};

use axum::extract::{Path, State};
use dashmap::DashMap;
use iref::UriBuf;
use oid4vci::{
    credential::CredentialOrConfigurationId,
    endpoints::credential::{CredentialResponse, ImmediateCredentialResponse},
    offer::{
        CredentialOfferGrants, CredentialOfferParameters, PreAuthorizedCodeGrant, TxCodeDefinition,
    },
    profile::{
        ProfileCredentialIssuerMetadata, ProfileCredentialRequest, ProfileCredentialResponse,
    },
    proof::{jwt::JwtProofVerifier, Proofs},
    server::{Oid4vciServer, ServerError},
    CredentialOffer, Oid4vciCredential, StandardProfile,
};
use open_auth2::AccessTokenBuf;
use rand::distr::{Alphanumeric, SampleString};
use ssi::{
    dids::{AnyDidMethod, VerificationMethodDIDResolver},
    prelude::AnyMethod,
};

use crate::{oauth2::PreAuthorizedCodeMetadata, Error, Server};

#[derive(Default)]
pub struct Oid4vciState {
    credential_offers: DashMap<String, CredentialOfferParameters>,
}

impl Oid4vciServer for Server {
    type Profile = StandardProfile;

    async fn metadata(
        &self,
    ) -> Result<Cow<'_, ProfileCredentialIssuerMetadata<Self::Profile>>, ServerError> {
        Ok(Cow::Owned(self.config.credential_issuer_metadata()))
    }

    async fn credential(
        &self,
        access_token: AccessTokenBuf,
        request: ProfileCredentialRequest<Self::Profile>,
    ) -> Result<ProfileCredentialResponse<Self::Profile>, ServerError> {
        let m = self
            .oauth2
            .access_token_metadata(&access_token)
            .ok_or(ServerError::Unauthorized)?;

        let (config, value) = match request.credential {
            CredentialOrConfigurationId::Credential(id) => self
                .config
                .get_credential(&id)
                .ok_or(ServerError::Unauthorized)?,
            CredentialOrConfigurationId::Configuration(id) => {
                let config = self
                    .config
                    .credential_configurations
                    .get(&id)
                    .ok_or(ServerError::Unauthorized)?;
                let mut credentials = config.credentials.iter();
                let (_, value) = credentials.next().ok_or(ServerError::Unauthorized)?;
                if credentials.next().is_some() {
                    return Err(ServerError::Unauthorized);
                }

                (config, value)
            }
        };

        let issuer = self.config.credential_issuer();

        let credentials = match &request.proofs {
            Some(proofs) => {
                let keys = match proofs {
                    Proofs::Jwt(jwts) => {
                        let jwk_resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(
                            AnyDidMethod::default(),
                        );
                        let verifier = JwtProofVerifier::new(&issuer, &jwk_resolver);

                        verifier
                            .verify_list(m.client_id.as_deref(), jwts)
                            .await
                            .map_err(|_| ServerError::Unauthorized)?
                    }
                    _ => todo!(),
                };

                let mut credentials = Vec::with_capacity(keys.len());

                for jwk in keys {
                    credentials.push(Oid4vciCredential::new(
                        config
                            .sign(
                                issuer.as_str(),
                                &self.jwk,
                                m.client_id.as_deref(),
                                value,
                                Some(&jwk),
                            )
                            .await,
                    ));
                }

                credentials
            }
            None => {
                vec![Oid4vciCredential::new(
                    config
                        .sign(
                            issuer.as_str(),
                            &self.jwk,
                            m.client_id.as_deref(),
                            value,
                            None,
                        )
                        .await,
                )]
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
