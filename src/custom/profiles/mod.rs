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

pub mod vc_sd_jwt;

pub struct CustomProfiles;
impl Profile for CustomProfiles {
    type CredentialConfiguration = CustomProfilesCredentialConfiguration;
    type AuthorizationDetailsObject = CustomProfilesAuthorizationDetailsObject;
    type CredentialRequest = CustomProfilesCredentialRequest;
    type CredentialResponse = CustomProfilesCredentialResponse;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CustomProfilesCredentialConfiguration {
    VcSdJwt(vc_sd_jwt::CredentialConfiguration),
}

impl CredentialConfigurationProfile for CustomProfilesCredentialConfiguration {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CustomProfilesAuthorizationDetailsObject {
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
    VcSdJwt(vc_sd_jwt::AuthorizationDetailsObjectWithFormat),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AuthorizationDetailsObjectWithCredentialConfigurationId {
    VcSdJwt(vc_sd_jwt::AuthorizationDetailsObject),
}

impl AuthorizationDetailsObjectProfile for CustomProfilesAuthorizationDetailsObject {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CustomProfilesCredentialRequest {
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

impl CredentialRequestProfile for CustomProfilesCredentialRequest {
    type Response = CustomProfilesCredentialResponse;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CredentialRequestWithFormat {
    VcSdJwt(vc_sd_jwt::CredentialRequestWithFormat),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CredentialRequestWithCredentialIdentifier {
    VcSdJwt(vc_sd_jwt::CredentialRequest),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CustomProfilesCredentialResponse;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CustomProfilesCredentialResponseType {
    VcSdJwt(<vc_sd_jwt::CredentialResponse as CredentialResponseProfile>::Type),
}

impl CredentialResponseProfile for CustomProfilesCredentialResponse {
    type Type = CustomProfilesCredentialResponseType;
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
