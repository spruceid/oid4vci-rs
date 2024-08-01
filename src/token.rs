use std::time::Duration;

use oauth2::AuthorizationCode;
use openidconnect::{
    core::{CoreErrorResponseType, CoreTokenType},
    ClientId, Nonce, RedirectUrl, StandardErrorResponse, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};

use crate::profiles::AuthorizationDetailsProfile;
use crate::{authorization::AuthorizationDetail, core::profiles::CoreProfilesAuthorizationDetails};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "grant_type")]
pub enum Request {
    AuthorizationCode {
        code: AuthorizationCode,
        redirect_uri: RedirectUrl,
        client_id: ClientId,
    },
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode {
        client_id: Option<ClientId>,
        #[serde(rename = "pre-authorized_code")]
        pre_authorized_code: String,
        #[serde(alias = "pin")]
        user_pin: Option<String>,
    },
    #[serde(rename = "urn:ietf:params:oauth:grant-type:refresh_token")]
    RefreshToken {
        client_id: Option<ClientId>,
        refresh_token: String,
        #[serde(alias = "pin")]
        user_pin: Option<String>,
    },
}

#[serde_as]
#[skip_serializing_none]
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ExtraResponseTokenFields<AD>
where
    AD: AuthorizationDetailsProfile,
{
    pub c_nonce: Option<Nonce>,
    pub c_nonce_expires_in: Option<Duration>,
    #[serde(bound = "AD: AuthorizationDetailsProfile")]
    pub authorization_details: Option<Vec<AuthorizationDetail<AD>>>,
}

pub type Response = StandardTokenResponse<
    ExtraResponseTokenFields<CoreProfilesAuthorizationDetails>,
    CoreTokenType,
>;

/// The following additional error codes, defined in RFC8628, are
/// mentioned and can be used as follow:
/// ```
/// use openidconnect::core::CoreErrorResponseType;
/// use oid4vci::token::Error;
///
/// let auth_pending_err = Error::new(
///   CoreErrorResponseType::Extension("authorization_pending".to_string()),
///   None,
///   None,
/// );
///
/// let slow_down_err = Error::new(
///   CoreErrorResponseType::Extension("slow_down".to_string()),
///   None,
///   None,
/// );
/// ```
pub type Error = StandardErrorResponse<CoreErrorResponseType>;

impl<AD> openidconnect::ExtraTokenFields for ExtraResponseTokenFields<AD> where
    AD: AuthorizationDetailsProfile
{
}
