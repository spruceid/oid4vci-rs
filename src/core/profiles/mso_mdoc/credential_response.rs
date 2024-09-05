use serde::{Deserialize, Serialize};

use crate::profiles::CredentialResponseProfile;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponse {
    credential: String,
}

impl CredentialResponse {
    pub fn new(credential: String) -> Self {
        Self { credential }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL response value"] {
            set_credential -> credential[String],
        }
    ];
}

impl CredentialResponseProfile for CredentialResponse {}
