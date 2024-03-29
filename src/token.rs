use std::time::Duration;

use oauth2::AuthorizationCode;
use openidconnect::{
    core::{CoreErrorResponseType, CoreTokenType},
    ClientId, Nonce, RedirectUrl, StandardErrorResponse, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ExtraResponseTokenFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<Nonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_pending: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<Duration>,
}

pub type Response = StandardTokenResponse<ExtraResponseTokenFields, CoreTokenType>;
pub type Error = StandardErrorResponse<CoreErrorResponseType>;

impl openidconnect::ExtraTokenFields for ExtraResponseTokenFields {}
