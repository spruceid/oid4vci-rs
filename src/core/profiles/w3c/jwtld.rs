use serde::{Deserialize, Serialize};

use crate::profiles::{
    AuthorizationDetaislProfile, CredentialMetadataProfile, CredentialOfferProfile,
    CredentialRequestProfile, CredentialResponseProfile,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Metadata {}
impl CredentialMetadataProfile for Metadata {
    type Request = Request;

    fn to_request(&self) -> Self::Request {
        Request::new()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Offer {}
impl CredentialOfferProfile for Offer {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetails {}
impl AuthorizationDetaislProfile for AuthorizationDetails {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct Request {}

impl Request {
    pub fn new() -> Self {
        Self {}
    }
}
impl CredentialRequestProfile for Request {
    type Response = Response;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Response {}
impl CredentialResponseProfile for Response {}
