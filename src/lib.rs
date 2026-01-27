//! This library provides a Rust implementation of [OID4VCI draft-13].
//!
//! [OID4VCI draft-13]: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-pre-authorized-code-flow>
//!
//! # Client Usage
//!
//! You can create a basic client implementation using the
//! [`SimpleOid4vciClient`] type as follows:
//!
//! ```ignore
//! use oid4vci::client::{SimpleOid4vciClient, Oid4vciClient, CredentialTokenState};
//!
//! // Setup client.
//! let client = SimpleOid4vciClient::new(client_id);
//!
//! // Start processing the credential offer.
//! let state = client
//!   .process_offer(&http_client, credential_offer)
//!   .await?;
//!
//! // Depending on the grant type, more authentication steps may be necessary.
//! let credential_token = match state {
//!   CredentialTokenState::RequiresAuthentication(state) => {
//!     let full_redirect_url = state.proceed(&http_client, redirect_url);
//!     let auth_code = do_authentication(full_redirect_url);
//!     state.proceed(auth_code)?
//!   }
//!   CredentialTokenState::RequiresTxCode(state) => {
//!     let tx_code = ask_for_tx_code(state.tx_code_definition());
//!     state.proceed(tx_code)?;
//!   }
//!   CredentialTokenState::Ready(token) => token,
//! };
//!
//! // Select what credential to issue.
//! let credential_id = credential_token.default_credential_id()?;
//!
//! // Create a proof of possession.
//! let nonce = credential_token.get_nonce(&http_client)?;
//! let proof = create_proof(nonce);
//!
//! // Issue credential.
//! let response = client
//!     .query_credential(&http_client, &credential_token, credential_id, Some(proof))?;
//! ```
//!
//! The client's behavior can be tweaked by replacing the
//! [`SimpleOid4vciClient`] type with a custom [`Oid4vciClient`] implementation.
//!
//! [`SimpleOid4vciClient`]: crate::client::SimpleOid4vciClient
//! [`Oid4vciClient`]: crate::client::Oid4vciClient
//!
//! # Server Usage
//!
//! Servers can be created by implementing the [`Oid4vciServer`] trait.
//! An example implementation can be found in the `example` folder.
//!
//! [`Oid4vciServer`]: crate::server::Oid4vciServer
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
pub mod nonce;
pub mod notification;
pub mod offer;
pub mod profile;
pub mod proof;
pub mod request;
pub mod response;
pub mod server;
pub mod types;
pub mod util;

pub use offer::CredentialOffer;
pub use profile::{AnyProfile, Profile, StandardProfile};
