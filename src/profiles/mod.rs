use std::fmt::Debug;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub mod core;
pub mod custom;

pub trait Profile {
    type CredentialConfiguration: CredentialConfigurationProfile;
    type AuthorizationDetailsObject: AuthorizationDetailsObjectProfile;
    type CredentialRequest: CredentialRequestProfile;
    type CredentialResponse: CredentialResponseProfile;
}
pub trait CredentialConfigurationProfile: Clone + Debug + DeserializeOwned + Serialize {}
pub trait AuthorizationDetailsObjectProfile: Debug + DeserializeOwned + Serialize {}
pub trait CredentialRequestProfile: Clone + Debug + DeserializeOwned + Serialize {
    type Response: CredentialResponseProfile;
}
pub trait CredentialResponseProfile: Debug + DeserializeOwned + Serialize {
    type Type: Clone + Debug + DeserializeOwned + Serialize;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ProfilesCredentialConfiguration {
    Core(core::profiles::CoreProfilesCredentialConfiguration),
    Custom(custom::profiles::CustomProfilesCredentialConfiguration),
}

impl CredentialConfigurationProfile for ProfilesCredentialConfiguration {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ProfilesAuthorizationDetailsObject {
    Core(core::profiles::CoreProfilesAuthorizationDetailsObject),
    Custom(custom::profiles::CustomProfilesAuthorizationDetailsObject),
}

impl AuthorizationDetailsObjectProfile for ProfilesAuthorizationDetailsObject {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ProfilesCredentialRequest {
    Core(core::profiles::CoreProfilesCredentialRequest),
    Custom(custom::profiles::CustomProfilesCredentialRequest),
}

impl CredentialRequestProfile for ProfilesCredentialRequest {
    type Response = ProfilesCredentialResponse;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ProfilesCredentialRequestWithFormat {
    Core(core::profiles::CredentialRequestWithFormat),
    Custom(custom::profiles::CredentialRequestWithFormat),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ProfilesCredentialResponse {
    Core(core::profiles::CoreProfilesCredentialResponse),
    Custom(custom::profiles::CustomProfilesCredentialResponse),
}

impl CredentialResponseProfile for ProfilesCredentialResponse {
    type Type = CredentialResponseType;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CredentialResponseType {
    Core(Box<core::profiles::CoreProfilesCredentialResponseType>),
    Custom(custom::profiles::CustomProfilesCredentialResponseType),
}

pub enum MetaProfile {
    Core(core::profiles::CoreProfiles),
    Custom(custom::profiles::CustomProfiles),
}

impl Profile for MetaProfile {
    type CredentialConfiguration = ProfilesCredentialConfiguration;
    type AuthorizationDetailsObject = ProfilesAuthorizationDetailsObject;
    type CredentialRequest = ProfilesCredentialRequest;
    type CredentialResponse = ProfilesCredentialResponse;
}

pub mod client {

    use crate::client;

    use super::MetaProfile;

    pub type Client = client::Client<MetaProfile>;
}

pub mod metadata {
    use crate::metadata;

    use super::ProfilesCredentialConfiguration;

    pub type CredentialIssuerMetadata =
        metadata::CredentialIssuerMetadata<ProfilesCredentialConfiguration>;
}
