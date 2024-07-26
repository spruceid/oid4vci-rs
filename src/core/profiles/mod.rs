use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::profiles::{
    AuthorizationDetaislProfile, CredentialMetadataProfile, CredentialOfferProfile,
    CredentialRequestProfile, CredentialResponseProfile, Profile,
};

pub mod isomdl;
pub mod w3c;

pub struct CoreProfiles {}
impl Profile for CoreProfiles {
    type Metadata = CoreProfilesMetadata;
    type Offer = CoreProfilesOffer;
    type Authorization = CoreProfilesAuthorizationDetails;
    type Credential = CoreProfilesRequest;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "format")]
pub enum CoreProfilesMetadata {
    #[serde(rename = "jwt_vc_json")]
    JWTVC(w3c::jwt::Metadata),
    #[serde(rename = "jwt_vc_json-ld")]
    JWTLDVC(w3c::jwtld::Metadata),
    #[serde(rename = "ldp_vc")]
    LDVC(w3c::ldp::Metadata),
    #[serde(rename = "mso_mdoc")]
    ISOmDL(isomdl::Metadata),
}
impl CredentialMetadataProfile for CoreProfilesMetadata {
    type Request = CoreProfilesRequest;

    fn to_request(&self) -> Self::Request {
        match self {
            CoreProfilesMetadata::JWTVC(m) => Self::Request::JWTVC(m.to_request()),
            CoreProfilesMetadata::JWTLDVC(m) => Self::Request::JWTLDVC(m.to_request()),
            CoreProfilesMetadata::LDVC(m) => Self::Request::LDVC(m.to_request()),
            CoreProfilesMetadata::ISOmDL(m) => Self::Request::ISOmDL(m.to_request()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "format")]
pub enum CoreProfilesOffer {
    #[serde(rename = "jwt_vc_json")]
    JWTVC(w3c::jwt::Offer),
    #[serde(rename = "jwt_vc_json-ld")]
    JWTLDVC(w3c::jwtld::Offer),
    #[serde(rename = "ldp_vc")]
    LDVC(w3c::ldp::Offer),
    #[serde(rename = "mso_mdoc")]
    ISOmDL(isomdl::Offer),
}
impl CredentialOfferProfile for CoreProfilesOffer {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "format")]
pub enum CoreProfilesAuthorizationDetails {
    #[serde(rename = "jwt_vc_json")]
    JWTVC(w3c::jwt::AuthorizationDetails),
    #[serde(rename = "jwt_vc_json-ld")]
    JWTLDVC(w3c::jwtld::AuthorizationDetails),
    #[serde(rename = "ldp_vc")]
    LDVC(w3c::ldp::AuthorizationDetails),
    #[serde(rename = "mso_mdoc")]
    ISOmDL(isomdl::AuthorizationDetails),
}
impl AuthorizationDetaislProfile for CoreProfilesAuthorizationDetails {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "format")]
pub enum CoreProfilesRequest {
    #[serde(rename = "jwt_vc_json")]
    JWTVC(w3c::jwt::Request),
    #[serde(rename = "jwt_vc_json-ld")]
    JWTLDVC(w3c::jwtld::Request),
    #[serde(rename = "ldp_vc")]
    LDVC(w3c::ldp::Request),
    #[serde(rename = "mso_mdoc")]
    ISOmDL(isomdl::Request),
}
impl CredentialRequestProfile for CoreProfilesRequest {
    type Response = CoreProfilesResponse;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "format")]
pub enum CoreProfilesResponse {
    #[serde(rename = "jwt_vc_json")]
    JWTVC(w3c::jwt::Response),
    #[serde(rename = "jwt_vc_json-ld")]
    JWTLDVC(w3c::jwtld::Response),
    #[serde(rename = "ldp_vc")]
    LDVC(w3c::ldp::Response),
    #[serde(rename = "mso_mdoc")]
    ISOmDL(isomdl::Response),
}
impl CredentialResponseProfile for CoreProfilesResponse {}
