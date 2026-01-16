use iref::UriBuf;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::types::IssuerState;

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationCodeGrant {
    pub issuer_state: Option<IssuerState>,
    pub authorization_server: Option<UriBuf>,
}

impl AuthorizationCodeGrant {
    pub fn new(issuer_state: Option<IssuerState>, authorization_server: Option<UriBuf>) -> Self {
        Self {
            issuer_state,
            authorization_server,
        }
    }
}
