use crate::{
    authorization::AnyCredentialAuthorizationParams,
    issuer::metadata::AnyCredentialFormatConfiguration, request::AnyCredentialRequestParams,
};

use super::Profile;

/// Format-agnostic profile.
///
/// Accepts any format, but won't try to interpret anything.
pub struct AnyProfile;

impl Profile for AnyProfile {
    type Format = String;
    type FormatConfiguration = AnyCredentialFormatConfiguration;
    type AuthorizationParams = AnyCredentialAuthorizationParams;
    type RequestParams = AnyCredentialRequestParams;
    type Credential = serde_json::Value;
}
