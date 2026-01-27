//! [RFC 9396]: OAuth 2.0 Rich Authorization Requests.
//!
//! [RFC 9396]: <https://www.rfc-editor.org/rfc/rfc9396.html#name-authorization-request>
use std::fmt::Debug;

use indexmap::IndexMap;
use iref::UriBuf;
use oauth2::{CodeTokenRequest, ErrorResponse, TokenResponse};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    authorization::pre_authorized_code::PreAuthorizedCodeTokenRequest,
    issuer::metadata::ClaimDescription,
};

pub trait AuthorizationDetailsObject: Serialize + DeserializeOwned {
    /// Identifier of the authorization detail type.
    fn r#type(&self) -> &str;
}

/// Authorization details object.
///
/// Implementors *must* ensure authorization details objects are always
/// serializable as JSON, otherwise users of this trait may panic.
pub trait TokenRequestAuthorizationDetails: Sized {
    /// Specifies the authorization details that the client wants the
    /// Authorization Server to assign to this access token.
    fn set_authorization_details<T: AuthorizationDetailsObject>(self, objects: &[T]) -> Self;
}

impl<'a, TE, TR> TokenRequestAuthorizationDetails for PreAuthorizedCodeTokenRequest<'a, TE, TR>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
{
    fn set_authorization_details<T: AuthorizationDetailsObject>(self, objects: &[T]) -> Self {
        if objects.is_empty() {
            self
        } else {
            self.add_extra_param(
                "authorization_details",
                serde_json::to_string(objects)
                    // UNWRAP SAFETY: All authorization details object can be serialized as JSON.
                    .unwrap(),
            )
        }
    }
}

impl<'a, TE, TR> TokenRequestAuthorizationDetails for CodeTokenRequest<'a, TE, TR>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
{
    fn set_authorization_details<T: AuthorizationDetailsObject>(self, objects: &[T]) -> Self {
        if objects.is_empty() {
            self
        } else {
            self.add_extra_param(
                "authorization_details",
                serde_json::to_string(objects)
                    // UNWRAP SAFETY: All authorization details object can be serialized as JSON.
                    .unwrap(),
            )
        }
    }
}

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

/// Credential format authorization details parameters.
///
/// Specifies format-specific parameters in a
/// [`CredentialAuthorizationDetailsObject`].
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-5.1.1>
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
