use std::collections::HashMap;

use isomdl::definitions::device_request::{DataElementIdentifier, NameSpace};
use serde::{Deserialize, Serialize};

pub mod authorization_detail;
pub mod credential_configuration;
pub mod credential_request;
pub mod credential_response;

pub use authorization_detail::{AuthorizationDetail, AuthorizationDetailWithFormat};
pub use credential_configuration::CredentialConfiguration;
pub use credential_request::{CredentialRequest, CredentialRequestWithFormat};
pub use credential_response::CredentialResponse;

pub const FORMAT_IDENTIFIER: &str = "mso_mdoc";

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum Format {
    #[default]
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,
}

pub type Claims<T> = HashMap<NameSpace, HashMap<DataElementIdentifier, T>>;
