use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct Oid4vciCredential<T = serde_json::Value> {
    #[serde(rename = "credential")]
    pub value: T,
}

impl<T> Oid4vciCredential<T> {
    pub fn new(value: T) -> Self {
        Self { value }
    }
}

/// Credential or configuration identifier.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CredentialOrConfigurationId {
    /// Identifies a Credential Dataset that is requested for issuance.
    ///
    /// To be used when the Token Response included a Credential Authorization
    /// Details Object.
    #[serde(rename = "credential_identifier")]
    Credential(String),

    /// Identifies a Credential Configuration, defined in the
    /// Credential Issuer Metadata, that is requested for issuance.
    ///
    /// It must be a key of
    /// [`CredentialIssuerMetadata::credential_configurations_supported`].
    /// The associated [`CredentialConfiguration::scope`] value must match one
    /// of the scopes included in the Authorization Request.
    ///
    /// [`CredentialIssuerMetadata::credential_configurations_supported`]: crate::issuer::CredentialIssuerMetadata::credential_configurations_supported
    /// [`CredentialConfiguration::scope`]: crate::issuer::metadata::CredentialConfiguration::scope
    #[serde(rename = "credential_configuration_id")]
    Configuration(String),
}

impl CredentialOrConfigurationId {
    pub fn as_ref(&self) -> CredentialOrConfigurationIdRef<'_> {
        match self {
            Self::Credential(id) => CredentialOrConfigurationIdRef::Credential(id),
            Self::Configuration(id) => CredentialOrConfigurationIdRef::Configuration(id),
        }
    }
}

/// Credential or configuration identifier reference.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum CredentialOrConfigurationIdRef<'a> {
    /// Identifies a Credential Dataset that is requested for issuance.
    ///
    /// To be used when the Token Response included a Credential Authorization
    /// Details Object.
    #[serde(rename = "credential_identifier")]
    Credential(&'a str),

    /// Identifies a Credential Configuration, defined in the
    /// Credential Issuer Metadata, that is requested for issuance.
    ///
    /// It must be a key of
    /// [`CredentialIssuerMetadata::credential_configurations_supported`].
    /// The associated [`CredentialConfiguration::scope`] value must match one
    /// of the scopes included in the Authorization Request.
    ///
    /// [`CredentialIssuerMetadata::credential_configurations_supported`]: crate::issuer::CredentialIssuerMetadata::credential_configurations_supported
    /// [`CredentialConfiguration::scope`]: crate::issuer::metadata::CredentialConfiguration::scope
    #[serde(rename = "credential_configuration_id")]
    Configuration(&'a str),
}

impl<'a> From<&'a CredentialOrConfigurationId> for CredentialOrConfigurationIdRef<'a> {
    fn from(value: &'a CredentialOrConfigurationId) -> Self {
        value.as_ref()
    }
}
