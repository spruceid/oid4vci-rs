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

/// A type representing the data contained in one element of the `credential_configurations_supported`
/// field of an issuer metadata response. This contains some fields that are particular to the different
/// credential formats that the issuer can return.
/// See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#section-11.2.3-2.11.1
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ProfilesCredentialConfiguration {
    Core(core::profiles::CoreProfilesCredentialConfiguration),
    Custom(custom::profiles::CustomProfilesCredentialConfiguration),
}

impl CredentialConfigurationProfile for ProfilesCredentialConfiguration {}

/// A type representing the data contained in the `authorization_details` parameter of an authorization
/// request. This may contain fields that are specific to particular credential formats that the
/// issuer can return.
/// See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#section-5.1.1
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ProfilesAuthorizationDetailsObject {
    Core(core::profiles::CoreProfilesAuthorizationDetailsObject),
    Custom(custom::profiles::CustomProfilesAuthorizationDetailsObject),
}

impl AuthorizationDetailsObjectProfile for ProfilesAuthorizationDetailsObject {}

// TODO (SKIT-797): Profiles no longer have specific fields in the credential request data structure as of
// draft 13. This should be removed.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ProfilesCredentialRequest {
    Core(core::profiles::CoreProfilesCredentialRequest),
    Custom(custom::profiles::CustomProfilesCredentialRequest),
}

impl CredentialRequestProfile for ProfilesCredentialRequest {
    type Response = ProfilesCredentialResponse;
}

// TODO (SKIT-797): Profiles no longer have specific fields in the credential request data structure as of
// draft 13. This should be removed.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ProfilesCredentialRequestWithFormat {
    Core(core::profiles::CredentialRequestWithFormat),
    Custom(custom::profiles::CredentialRequestWithFormat),
}

/// A type representing the data contained in the credential response returned by the issuer
/// This may contain fields that are specific to particular credential formats that the
/// issuer can return.
/// See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#name-credential-response
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

/// A profile that represents any type of credential configuration that an OID4VCI service may return
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
