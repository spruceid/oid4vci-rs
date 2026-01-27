use iref::UriBuf;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct AuthorizationCodeGrant {
    pub issuer_state: Option<String>,
    pub authorization_server: Option<UriBuf>,
}

impl AuthorizationCodeGrant {
    pub fn new(issuer_state: Option<String>, authorization_server: Option<UriBuf>) -> Self {
        Self {
            issuer_state,
            authorization_server,
        }
    }
}
