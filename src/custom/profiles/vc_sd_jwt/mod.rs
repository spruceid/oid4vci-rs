pub mod authorization_detail;
pub mod credential_configuration;
pub mod credential_request;
pub mod credential_response;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const FORMAT_IDENTIFIER: &str = "vc+sd-jwt";
pub use authorization_detail::{AuthorizationDetailsObject, AuthorizationDetailsObjectWithFormat};
pub use credential_configuration::CredentialConfiguration;
pub use credential_request::{CredentialRequest, CredentialRequestWithFormat};
pub use credential_response::CredentialResponse;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum Format {
    #[default]
    #[serde(rename = "vc+sd-jwt")]
    VcSdJwt,
}

pub type Claims<T> = HashMap<String, Box<MaybeNestedClaims<T>>>;

// Object containing a list of name/value pairs, where each name identifies a claim offered in the Credential.
// The value can be another such object (nested data structures), or an array of such objects.
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#appendix-A.1.1.2-3.1.2.2.1
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum MaybeNestedClaims<T> {
    Object(Claims<T>),
    Array(Vec<Claims<T>>),
    Leaf(T),
}
