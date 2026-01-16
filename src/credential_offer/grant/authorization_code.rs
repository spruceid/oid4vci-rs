use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::types::{IssuerState, IssuerUrl};

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationCodeGrant {
    issuer_state: Option<IssuerState>,
    authorization_server: Option<IssuerUrl>,
}

impl AuthorizationCodeGrant {
    pub fn new(issuer_state: Option<IssuerState>, authorization_server: Option<IssuerUrl>) -> Self {
        Self {
            issuer_state,
            authorization_server,
        }
    }
    field_getters_setters![
        pub self [self] ["authorization code grants"] {
            set_issuer_state -> issuer_state[Option<IssuerState>],
            set_authorization_server -> authorization_server[Option<IssuerUrl>],
        }
    ];
}
