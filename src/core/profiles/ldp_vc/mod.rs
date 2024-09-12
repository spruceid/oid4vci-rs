pub mod authorization_detail;
pub mod credential_configuration;
pub mod credential_request;
pub mod credential_response;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const FORMAT_IDENTIFIER: &str = "ldp_vc";
pub use authorization_detail::AuthorizationDetailsObject;
pub use credential_request::CredentialRequest;
pub use credential_response::CredentialResponse;

pub type AuthorizationDetailWithFormat =
    authorization_detail::AuthorizationDetailsObjectWithFormat<Format>;
pub type CredentialConfiguration = credential_configuration::CredentialConfiguration<Format>;
pub type CredentialRequestWithFormat = credential_request::CredentialRequestWithFormat<Format>;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum Format {
    #[default]
    #[serde(rename = "ldp_vc")]
    LdpVc,
}

pub type CredentialSubjectClaims<T> = HashMap<String, Box<MaybeNestedClaims<T>>>;

// Object containing a list of name/value pairs, where each name identifies a claim offered in the Credential.
// The value can be another such object (nested data structures), or an array of such objects.
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#appendix-A.1.2.2-3.1.2.3.1
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum MaybeNestedClaims<T> {
    Object(CredentialSubjectClaims<T>),
    Array(Vec<CredentialSubjectClaims<T>>),
    Leaf(T),
}
