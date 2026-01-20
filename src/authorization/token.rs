use std::time::Duration;

use oauth2::{
    basic::BasicTokenType, AuthorizationCode, ClientId, ExtraTokenFields, RedirectUrl,
    RefreshToken, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::{
    authorization::{CredentialAuthorizationDetailsObject, CredentialAuthorizationParams},
    profile::StandardCredentialAuthorizationParams,
    types::{Nonce, PreAuthorizedCode, TxCode},
};

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
        pre_authorized_code: PreAuthorizedCode,
        tx_code: Option<TxCode>,
    },
    #[serde(rename = "refresh_token")]
    RefreshToken {
        client_id: Option<ClientId>,
        refresh_token: RefreshToken,
    },
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(bound = "T: CredentialAuthorizationParams")]
pub struct ExtraResponseTokenFields<T: CredentialAuthorizationParams> {
    pub c_nonce: Option<Nonce>,
    pub c_nonce_expires_in: Option<Duration>,
    pub authorization_details: Option<Vec<CredentialAuthorizationDetailsObject<T>>>,
}

pub type Response<T = StandardCredentialAuthorizationParams> =
    StandardTokenResponse<ExtraResponseTokenFields<T>, BasicTokenType>;

impl<T> ExtraTokenFields for ExtraResponseTokenFields<T> where T: CredentialAuthorizationParams {}
