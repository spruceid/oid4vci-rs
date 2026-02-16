use crate::{
    authorization::authorization_details::AnyCredentialAuthorizationParams,
    endpoints::credential::AnyCredentialRequestParams,
    issuer::metadata::AnyCredentialFormatConfiguration,
};

use super::Profile;

/// Format-agnostic profile.
///
/// Accepts any format, but won't try to interpret anything.
pub struct AnyProfile;

impl Profile for AnyProfile {
    type Format = String;
    type FormatMetadata = AnyCredentialFormatConfiguration;
    type AuthorizationParams = AnyCredentialAuthorizationParams;
    type RequestParams = AnyCredentialRequestParams;
    type Credential = serde_json::Value;
}
