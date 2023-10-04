use serde::{Deserialize, Serialize};

use crate::credential_profiles::{
    AuthorizationDetaislProfile, CredentialMetadataProfile, CredentialOfferProfile,
    CredentialRequestProfile, CredentialResponseProfile,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Metadata {}
impl CredentialMetadataProfile for Metadata {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Offer {}
impl CredentialOfferProfile for Offer {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetails {}
impl AuthorizationDetaislProfile for AuthorizationDetails {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request {}
impl CredentialRequestProfile for Request {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Response {}
impl CredentialResponseProfile for Response {}
