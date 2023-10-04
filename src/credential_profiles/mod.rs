use std::fmt::Debug;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub mod isomdl;
pub mod w3c;

pub trait CredentialMetadataProfile: Debug + DeserializeOwned + Serialize {}
pub trait CredentialOfferProfile: Debug + DeserializeOwned + Serialize {}
pub trait AuthorizationDetaislProfile: Debug + DeserializeOwned + Serialize {}
pub trait CredentialRequestProfile: Debug + DeserializeOwned + Serialize {}
pub trait CredentialResponseProfile: Debug + DeserializeOwned + Serialize {}

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
impl CredentialMetadataProfile for CoreProfilesMetadata {}

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
impl CredentialRequestProfile for CoreProfilesRequest {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
