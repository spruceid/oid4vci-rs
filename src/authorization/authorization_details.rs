//! [RFC 9396]: OAuth 2.0 Rich Authorization Requests.
//!
//! [RFC 9396]: <https://www.rfc-editor.org/rfc/rfc9396.html#name-authorization-request>
use std::fmt::Debug;

use indexmap::IndexMap;
use iref::UriBuf;
use open_auth2::ext::rar::AuthorizationDetailsObject;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::issuer::metadata::ClaimDescription;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    bound = "C: CredentialAuthorizationParams",
    tag = "type",
    rename = "openid_credential"
)]
pub struct CredentialAuthorizationDetailsRequest<C: CredentialAuthorizationParams> {
    /// Unique identifier of the Credential Configuration.
    pub credential_configuration_id: String,

    /// Requested claims.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub claims: Vec<ClaimDescription>,

    /// Locations.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub locations: Vec<UriBuf>,

    /// Format-specific parameters.
    #[serde(flatten)]
    pub params: C,
}

impl<C: CredentialAuthorizationParams> AuthorizationDetailsObject
    for CredentialAuthorizationDetailsRequest<C>
{
    fn r#type(&self) -> &str {
        OPENID_CREDENTIAL
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    bound = "C: CredentialAuthorizationParams",
    tag = "type",
    rename = "openid_credential"
)]
pub struct CredentialAuthorizationDetailsResponse<
    C: CredentialAuthorizationParams = AnyCredentialAuthorizationParams,
> {
    /// Credential Configuration identifier.
    pub credential_configuration_id: String,

    /// Authorized claims.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub claims: Vec<ClaimDescription>,

    /// Credential Dataset that can be issued using the given Access Token.
    ///
    /// The Wallet *must* use these identifiers in subsequent Credential
    /// Requests with the given Access Token.
    pub credential_identifiers: Vec<String>, // TODO should be non-empty.

    /// Format-specific parameters.
    #[serde(flatten)]
    pub params: C,
}

impl<C> AuthorizationDetailsObject for CredentialAuthorizationDetailsResponse<C>
where
    C: CredentialAuthorizationParams,
{
    fn r#type(&self) -> &str {
        OPENID_CREDENTIAL
    }
}

/// Credential format authorization details parameters.
///
/// Specifies format-specific parameters in a
/// [`AuthorizationDetailsObject`].
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-authorization-details>
pub trait CredentialAuthorizationParams:
    'static + Send + Sync + Debug + Serialize + DeserializeOwned
{
}

pub type AnyCredentialAuthorizationParams = IndexMap<String, serde_json::Value>;

impl CredentialAuthorizationParams for AnyCredentialAuthorizationParams {}

pub const OPENID_CREDENTIAL: &str = "openid_credential";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenIdCredential;

impl Serialize for OpenIdCredential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        OPENID_CREDENTIAL.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OpenIdCredential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s == OPENID_CREDENTIAL {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("expected \"{OPENID_CREDENTIAL}\""))
        }
    }
}
