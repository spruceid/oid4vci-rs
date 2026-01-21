//! This library provides a Rust implementation of [OID4VCI draft-13].
//!
//! [OID4VCI draft-13]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-pre-authorized-code-flow>
//!
//! # Protocol Overview
//!
//! Here is a simplified overview of the OID4VCI protocol, referencing the
//! various types and methods implementing it.
//!
//! ## Offer
//!
//! 1. *Out-of-band credential offer*: Issuer sends a [`CredentialOffer`] to the
//!    Wallet. This can be done through various methods like a QR-code, deep
//!    link, etc.
//! 2. *Issuer metadata resolution*: Wallet fetches the
//!    [`CredentialIssuerMetadata`]. This object is [`Discoverable`] behind the
//!    `/.well-known/openid-credential-issuer` endpoint.
//!
//! All the code related to Credential Offer is located in the
//! [`offer`] module.
//!
//! [`CredentialOffer`]: crate::offer::CredentialOffer
//! [`CredentialIssuerMetadata`]: crate::issuer::metadata::CredentialIssuerMetadata
//! [`Discoverable`]: crate::util::discoverable::Discoverable
//!
//! ## Authorization
//!
//! 3. *Authorization server resolution*: Wallet fetches the
//!    [`AuthorizationServerMetadata`]. This object is [`Discoverable`] behind
//!    the `/.well-known/oauth-authorization-server` endpoint.
//! 4. Wallet sends an [`AuthorizationRequest`] to the Authorization Server,
//!    specifying what types of Credential(s) it is ready to be issued.
//! 5. Authorization Server returns an [`AuthorizationCode`].
//! 6. Wallet sends a Token Request.
//! 7. Authorization Server returns a Token Response, with an Access Token.
//!
//! All the code related to Authorization is located in the [`authorization`]
//! module.
//!
//! [`AuthorizationServerMetadata`]: crate::authorization::server::metadata::AuthorizationServerMetadata
//! [`AuthorizationRequest`]: crate::authorization::AuthorizationRequest
//! [`AuthorizationCode`]: oauth2::AuthorizationCode
//!
//! ## Issuance
//!
//! 8. Wallet sends a [`CredentialRequest`] to the Issuer, with the Access Token.
//! 9. Issuer returns a [`CredentialResponse`], with the Credential(s).
//!
//! [`CredentialRequest`]: crate::request::CredentialRequest
//! [`CredentialResponse`]: crate::response::CredentialResponse
//!
//! # Profiles
//!
//! The supported credential formats are defined by the [`Profile`] trait
//! implementation. This library provides two built-in profiles:
//! - [`AnyProfile`]: Format-agnostic profile. Accepts everything, but won't
///   interpret anything.
/// - [`StandardProfile`]: Implements the profile defined by the OID4VCI
///   specification's [Appendix A].
///
/// [Appendix A]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#appendix-A>
pub use oauth2;

pub mod authorization;
pub mod client;
pub mod encryption;
pub mod issuer;
pub mod notification;
pub mod offer;
pub mod profile;
pub mod proof_of_possession;
pub mod request;
pub mod response;
pub mod types;
pub mod util;

pub use offer::CredentialOffer;
pub use profile::{AnyProfile, Profile, StandardProfile};
