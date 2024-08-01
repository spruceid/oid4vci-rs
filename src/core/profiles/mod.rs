use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::profiles::{
    AuthorizationDetailsProfile, CredentialMetadataProfile, CredentialOfferProfile,
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
            CoreProfilesMetadata::JWTVC(m) => {
                Self::Request::Value(ValueRequest::JWTVC(m.to_request()))
            }
            CoreProfilesMetadata::JWTLDVC(m) => {
                Self::Request::Value(ValueRequest::JWTLDVC(m.to_request()))
            }
            CoreProfilesMetadata::LDVC(m) => {
                Self::Request::Value(ValueRequest::LDVC(m.to_request()))
            }
            CoreProfilesMetadata::ISOmDL(m) => {
                Self::Request::Value(ValueRequest::ISOmDL(m.to_request()))
            }
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
pub struct ReferencedAuthorizationDetails {
    credential_configuration_id: String,

    #[serde(
        default,
        skip_serializing,
        deserialize_with = "crate::deny_field::deny_field",
        rename = "format"
    )]
    _format: (),
}

impl ReferencedAuthorizationDetails {
    pub fn new(credential_configuration_id: String) -> Self {
        Self {
            credential_configuration_id,
            _format: (),
        }
    }

    field_getters_setters![
        pub self [self] ["Authorization Details definition value"] {
            set_credential_configuration_id -> credential_configuration_id[String],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "format")]
pub enum ValueAuthorizationDetails {
    #[serde(rename = "jwt_vc_json")]
    JWTVC(w3c::jwt::AuthorizationDetails),
    #[serde(rename = "jwt_vc_json-ld")]
    JWTLDVC(w3c::jwtld::AuthorizationDetails),
    #[serde(rename = "ldp_vc")]
    LDVC(w3c::ldp::AuthorizationDetails),
    #[serde(rename = "mso_mdoc")]
    ISOmDL(isomdl::AuthorizationDetails),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CoreProfilesAuthorizationDetails {
    Value(ValueAuthorizationDetails),
    Referenced(ReferencedAuthorizationDetails),
}
impl AuthorizationDetailsProfile for CoreProfilesAuthorizationDetails {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReferencedRequest {
    credential_identifier: String,

    #[serde(
        default,
        skip_serializing,
        deserialize_with = "crate::deny_field::deny_field",
        rename = "format"
    )]
    _format: (),
}

impl ReferencedRequest {
    pub fn new(credential_identifier: String) -> Self {
        Self {
            credential_identifier,
            _format: (),
        }
    }

    field_getters_setters![
        pub self [self] ["Authorization Details definition value"] {
            set_credential_identifier -> credential_identifier[String],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "format")]
pub enum ValueRequest {
    #[serde(rename = "jwt_vc_json")]
    JWTVC(w3c::jwt::Request),
    #[serde(rename = "jwt_vc_json-ld")]
    JWTLDVC(w3c::jwtld::Request),
    #[serde(rename = "ldp_vc")]
    LDVC(w3c::ldp::Request),
    #[serde(rename = "mso_mdoc")]
    ISOmDL(isomdl::Request),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CoreProfilesRequest {
    Value(ValueRequest),
    Referenced(ReferencedRequest),
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
