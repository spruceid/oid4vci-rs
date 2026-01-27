use oauth2::{
    basic::BasicTokenType, AuthorizationCode, ClientId, ExtraTokenFields, RedirectUrl,
    RefreshToken, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};

use crate::authorization::authorization_details::{
    AnyCredentialAuthorizationParams, CredentialAuthorizationDetailsResponse,
    CredentialAuthorizationParams,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "grant_type", rename = "authorization_code")]
pub struct AuthorizationCodeTokenRequest {
    pub code: AuthorizationCode,
    pub redirect_uri: RedirectUrl,
    pub client_id: ClientId,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(
    tag = "grant_type",
    rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)]
pub struct PreAuthorizedCodeTokenRequest {
    pub client_id: Option<ClientId>,
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    pub tx_code: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "grant_type", rename = "refresh_token")]
pub struct RefreshTokenRequest {
    pub client_id: Option<ClientId>,
    pub refresh_token: RefreshToken,
}

/// Credential-specific Token fields.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(bound = "T: CredentialAuthorizationParams")]
pub struct CredentialTokenParams<
    T: CredentialAuthorizationParams = AnyCredentialAuthorizationParams,
> {
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub authorization_details: Vec<CredentialAuthorizationDetailsResponse<T>>,
}

/// Credential Token Response.
pub type CredentialTokenResponse<T = AnyCredentialAuthorizationParams> =
    StandardTokenResponse<CredentialTokenParams<T>, BasicTokenType>;

impl<T> ExtraTokenFields for CredentialTokenParams<T> where T: CredentialAuthorizationParams {}
