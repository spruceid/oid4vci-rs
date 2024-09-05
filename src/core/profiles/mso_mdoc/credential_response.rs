use serde::{Deserialize, Serialize};

use crate::profiles::CredentialResponseProfile;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponse;

impl CredentialResponseProfile for CredentialResponse {
    type Type = String;
}
