use serde::{de::DeserializeOwned, Serialize};

use crate::{
    authorization::authorization_details::{
        CredentialAuthorizationDetailsRequest, CredentialAuthorizationDetailsResponse,
        CredentialAuthorizationParams,
    },
    endpoints::credential::{CredentialRequest, CredentialRequestParams, CredentialResponse},
    issuer::{metadata::CredentialFormatMetadata, CredentialIssuerMetadata},
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
/// [Appendix A]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-format-profiles>
pub trait Profile: 'static {
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
    type FormatMetadata: CredentialFormatMetadata<Format = Self::Format>;

    /// Credential format authorization details parameters.
    ///
    /// Format-specific parameters for each [`AuthorizationDetailsObject`].
    ///
    /// [`AuthorizationDetailsObject`]: open_auth2::ext::rar::AuthorizationDetailsObject
    type AuthorizationParams: CredentialAuthorizationParams;

    /// Credential format request parameters.
    ///
    /// Format-specific parameters for each [`CredentialRequest`].
    ///
    /// [`CredentialRequest`]: crate::endpoints::credential::CredentialRequest
    type RequestParams: CredentialRequestParams;

    /// Credential payload type.
    ///
    /// Data type returned in a [`CredentialResponse`].
    ///
    /// [`CredentialResponse`]: crate::endpoints::credential::CredentialResponse
    type Credential: 'static + Send + Sync + Serialize + DeserializeOwned;
}

pub type ProfileCredentialIssuerMetadata<P> =
    CredentialIssuerMetadata<<P as Profile>::FormatMetadata>;

pub type ProfileCredentialAuthorizationDetailsRequest<P> =
    CredentialAuthorizationDetailsRequest<<P as Profile>::AuthorizationParams>;

pub type ProfileCredentialAuthorizationDetailsResponse<P> =
    CredentialAuthorizationDetailsResponse<<P as Profile>::AuthorizationParams>;

pub type ProfileCredentialRequest<P> = CredentialRequest<<P as Profile>::RequestParams>;

pub type ProfileCredentialResponse<P> = CredentialResponse<<P as Profile>::Credential>;

// pub type ProfileAuthorizationRequestParams<P> =
//     AuthorizationRequestParams<<P as Profile>::AuthorizationParams>;
