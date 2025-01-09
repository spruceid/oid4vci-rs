use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const FORMAT_IDENTIFIER: &str = "jwt_vc_json-ld";
pub use super::jwt_vc_json::credential_response::CredentialResponse;
pub use super::ldp_vc::authorization_detail::AuthorizationDetailsObject;
pub use super::ldp_vc::credential_request::CredentialRequest;

pub type AuthorizationDetailWithFormat =
    super::ldp_vc::authorization_detail::AuthorizationDetailsObjectWithFormat<Format>;
pub type CredentialConfiguration =
    super::ldp_vc::credential_configuration::CredentialConfiguration<Format>;
pub type CredentialRequestWithFormat =
    super::ldp_vc::credential_request::CredentialRequestWithFormat<Format>;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum Format {
    #[default]
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd,
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
