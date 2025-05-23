use std::{collections::HashMap, fmt::Debug};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    profiles::{
        AuthorizationDetailsObjectProfile, CredentialConfigurationProfile,
        CredentialRequestProfile, CredentialResponseProfile, Profile,
    },
    types::{ClaimValueType, CredentialConfigurationId, LanguageTag},
};

pub mod jwt_vc_json;
pub mod jwt_vc_json_ld;
pub mod ldp_vc;
pub mod mso_mdoc;

pub struct CoreProfiles;
impl Profile for CoreProfiles {
    type CredentialConfiguration = CoreProfilesCredentialConfiguration;
    type AuthorizationDetailsObject = CoreProfilesAuthorizationDetailsObject;
    type CredentialRequest = CoreProfilesCredentialRequest;
    type CredentialResponse = CoreProfilesCredentialResponse;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CoreProfilesCredentialConfiguration {
    JwtVcJson(jwt_vc_json::CredentialConfiguration),
    JwtVcJsonLd(jwt_vc_json_ld::CredentialConfiguration),
    LdpVc(ldp_vc::CredentialConfiguration),
    MsoMdoc(mso_mdoc::CredentialConfiguration),
}

impl CredentialConfigurationProfile for CoreProfilesCredentialConfiguration {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CoreProfilesAuthorizationDetailsObject {
    WithFormat {
        #[serde(flatten)]
        inner: AuthorizationDetailsObjectWithFormat,
        #[serde(
            default,
            skip_serializing,
            deserialize_with = "crate::deny_field::deny_field",
            rename = "credential_identifier"
        )]
        _credential_identifier: (),
    },
    WithIdAndUnresolvedProfile {
        credential_configuration_id: CredentialConfigurationId,
        #[serde(flatten)]
        inner: HashMap<String, Value>,
        #[serde(
            default,
            skip_serializing,
            deserialize_with = "crate::deny_field::deny_field",
            rename = "format"
        )]
        _format: (),
    },
    #[serde(skip_deserializing)]
    WithId {
        credential_configuration_id: CredentialConfigurationId,
        #[serde(flatten)]
        inner: AuthorizationDetailsObjectWithCredentialConfigurationId,
        #[serde(
            default,
            skip_serializing,
            deserialize_with = "crate::deny_field::deny_field",
            rename = "format"
        )]
        _format: (),
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AuthorizationDetailsObjectWithFormat {
    JwtVcJson(jwt_vc_json::AuthorizationDetailsObjectWithFormat),
    JwtVcJsonLd(jwt_vc_json_ld::AuthorizationDetailWithFormat),
    LdpVc(ldp_vc::AuthorizationDetailWithFormat),
    MsoMdoc(mso_mdoc::AuthorizationDetailsObjectWithFormat),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AuthorizationDetailsObjectWithCredentialConfigurationId {
    JwtVcJson(jwt_vc_json::AuthorizationDetailsObject),
    JwtVcJsonLd(jwt_vc_json_ld::AuthorizationDetailsObject),
    LdpVc(ldp_vc::AuthorizationDetailsObject),
    MsoMdoc(mso_mdoc::AuthorizationDetailsObject),
}

impl AuthorizationDetailsObjectProfile for CoreProfilesAuthorizationDetailsObject {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CoreProfilesCredentialRequest {
    WithFormat {
        #[serde(flatten)]
        inner: CredentialRequestWithFormat,
        #[serde(
            default,
            skip_serializing,
            deserialize_with = "crate::deny_field::deny_field",
            rename = "credential_identifier"
        )]
        _credential_identifier: (),
    },
    WithIdAndUnresolvedProfile {
        credential_identifier: CredentialConfigurationId,
        #[serde(flatten)]
        inner: HashMap<String, Value>,
        #[serde(
            default,
            skip_serializing,
            deserialize_with = "crate::deny_field::deny_field",
            rename = "format"
        )]
        _format: (),
    },
    #[serde(skip_deserializing)]
    WithId {
        credential_identifier: CredentialConfigurationId,
        #[serde(flatten)]
        inner: CredentialRequestWithCredentialIdentifier,
        #[serde(
            default,
            skip_serializing,
            deserialize_with = "crate::deny_field::deny_field",
            rename = "format"
        )]
        _format: (),
    },
}

impl CredentialRequestProfile for CoreProfilesCredentialRequest {
    type Response = CoreProfilesCredentialResponse;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CredentialRequestWithFormat {
    JwtVcJson(jwt_vc_json::CredentialRequestWithFormat),
    JwtVcJsonLd(jwt_vc_json_ld::CredentialRequestWithFormat),
    LdpVc(ldp_vc::CredentialRequestWithFormat),
    MsoMdoc(mso_mdoc::CredentialRequestWithFormat),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CredentialRequestWithCredentialIdentifier {
    JwtVcJson(jwt_vc_json::CredentialRequest),
    JwtVcJsonLd(jwt_vc_json_ld::CredentialRequest),
    LdpVc(ldp_vc::CredentialRequest),
    MsoMdoc(mso_mdoc::CredentialRequest),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CoreProfilesCredentialResponse;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CoreProfilesCredentialResponseType {
    JwtVcJson(<jwt_vc_json::CredentialResponse as CredentialResponseProfile>::Type),
    JwtVcJsonLd(<jwt_vc_json_ld::CredentialResponse as CredentialResponseProfile>::Type),
    LdpVc(Box<<ldp_vc::CredentialResponse as CredentialResponseProfile>::Type>),
    MsoMdoc(Box<<mso_mdoc::CredentialResponse as CredentialResponseProfile>::Type>),
}

impl CredentialResponseProfile for CoreProfilesCredentialResponse {
    type Type = CoreProfilesCredentialResponseType;
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetailsObjectClaim {
    #[serde(default, skip_serializing_if = "is_false")]
    mandatory: bool,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialConfigurationClaim {
    #[serde(default, skip_serializing_if = "is_false")]
    mandatory: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value_type: Option<ClaimValueType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    display: Vec<ClaimDisplay>,
}

fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ClaimDisplay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    locale: Option<LanguageTag>,
    #[serde(flatten)]
    additional_fields: HashMap<String, Value>,
}
