use std::time::Duration;

use oauth2::basic::BasicTokenType;
use oauth2::{
    AuthorizationCode, ClientId, ExtraTokenFields, RedirectUrl, RefreshToken, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};

use crate::types::{Nonce, PreAuthorizedCode};
use crate::{authorization::AuthorizationDetail, core::profiles::CoreProfilesAuthorizationDetails};
use crate::{profiles::AuthorizationDetailsProfile, types::TxCode};

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

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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
    BasicTokenType,
>;

impl<AD> ExtraTokenFields for ExtraResponseTokenFields<AD> where AD: AuthorizationDetailsProfile {}
