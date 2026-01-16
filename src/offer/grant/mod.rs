use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

mod authorization_code;
mod pre_authorized_code;

pub use authorization_code::*;
pub use pre_authorized_code::*;

/// Credential Offer `grants` value.
#[skip_serializing_none]
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct CredentialOfferGrants {
    pub authorization_code: Option<AuthorizationCodeGrant>,

    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

impl CredentialOfferGrants {
    pub fn new(
        authorization_code: Option<AuthorizationCodeGrant>,
        pre_authorized_code: Option<PreAuthorizedCodeGrant>,
    ) -> Self {
        Self {
            authorization_code,
            pre_authorized_code,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.authorization_code.is_none() && self.pre_authorized_code.is_none()
    }
}
