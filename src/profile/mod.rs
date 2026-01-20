use crate::{
    authorization::CredentialAuthorizationParams, issuer::metadata::CredentialFormatMetadata,
    request::CredentialRequestParams,
};

mod any;
mod standard;

pub use any::*;
pub use standard::*;

/// Credential profile.
///
/// Specifies the what formats are supported.
///
/// This library provides two built-in profiles:
/// - [`AnyProfile`]: Format-agnostic profile. Accepts everything, but won't
///   interpret anything.
/// - [`StandardProfile`]: Implements the profile defined by the OID4VCI
///   specification's [Appendix A].
///
/// [Appendix A]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#appendix-A>
pub trait Profile {
    /// Credential format identifier.
    ///
    /// This types contains the identifiers of all the supported credential
    /// formats.
    type Format;

    /// Credential format metadata.
    ///
    /// Format-specific metadata provided by the [`CredentialIssuerMetadata`].
    ///
    /// [`CredentialIssuerMetadata`]: crate::issuer::CredentialIssuerMetadata
    type FormatConfiguration: CredentialFormatMetadata<Format = Self::Format>;

    /// Credential format authorization details parameters.
    ///
    /// Format-specific parameters for each
    /// [`CredentialAuthorizationDetailsObject`].
    ///
    /// [`CredentialAuthorizationDetailsObject`]: crate::authorization::CredentialAuthorizationDetailsObject
    type AuthorizationParams: CredentialAuthorizationParams<Format = Self::Format>;

    /// Credential format request parameters.
    ///
    /// Format-specific parameters for each [`CredentialRequest`].
    ///
    /// [`CredentialRequest`]: crate::request::CredentialRequest
    type RequestParams: CredentialRequestParams<Format = Self::Format>;

    /// Credential payload type.
    ///
    /// Data type returned in a [`CredentialResponse`].
    ///
    /// [`CredentialResponse`]: crate::response::CredentialResponse
    type Credential;
}
