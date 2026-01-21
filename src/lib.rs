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

pub use profile::{AnyProfile, Profile, StandardProfile};

#[cfg(test)]
mod test {
    use crate::{
        authorization::server::{metadata::GrantType, AuthorizationServerMetadata},
        client::Client,
        issuer::{metadata::CredentialConfiguration, CredentialIssuerMetadata},
        offer::CredentialOffer,
        profile::{
            w3c_vc::{W3cVcDefinitionRequest, W3cVcRequestParams},
            StandardCredentialFormatMetadata, StandardCredentialRequestParams, StandardFormat,
            W3cVcFormat,
        },
        request::CredentialFormatOrIdentifier,
        types::{CredentialConfigurationId, CredentialOfferRequest},
        util::discoverable::Discoverable,
    };
    use oauth2::{ClientId, RedirectUrl, TokenResponse};
    use url::Url;

    #[tokio::test]
    #[ignore]
    async fn manual() {
        let http_client = oauth2::reqwest::Client::new();

        // Get a credential offer from vc-playground.org.
        let credential_offer_request: Url = "".parse().unwrap();

        let credential_offer = CredentialOffer::from_request(
            CredentialOfferRequest::from_url_checked(credential_offer_request).unwrap(),
        )
        .unwrap()
        .resolve_async(&http_client)
        .await
        .unwrap();

        let credential_issuer_metadata = CredentialIssuerMetadata::discover_async(
            &credential_offer.credential_issuer,
            &http_client,
        )
        .await
        .unwrap();

        let targeted_credentials: Vec<(CredentialConfigurationId, CredentialConfiguration)> =
            credential_issuer_metadata
                .credential_configurations_supported
                .iter()
                .filter(|(id, _)| credential_offer.credential_configuration_ids.contains(id))
                .map(|(id, configuration)| (id.clone(), configuration.clone()))
                .collect();

        assert_eq!(targeted_credentials.len(), 1);

        let grant = credential_offer
            .grants
            .pre_authorized_code
            .as_ref()
            .unwrap();
        let authorization_server = grant.authorization_server.as_deref();

        let authorization_server_metadata =
            AuthorizationServerMetadata::discover_from_credential_issuer_metadata_async(
                &http_client,
                &credential_issuer_metadata,
                Some(&GrantType::PreAuthorizedCode),
                authorization_server,
            )
            .await
            .unwrap();

        let client: Client = Client::from_issuer_metadata(
            ClientId::new("test".to_owned()),
            RedirectUrl::new("test://".to_owned()).unwrap(),
            credential_issuer_metadata,
            authorization_server_metadata,
        );

        let token_response = client
            .exchange_pre_authorized_code(
                credential_offer
                    .grants
                    .pre_authorized_code
                    .as_ref()
                    .unwrap()
                    .pre_authorized_code
                    .clone(),
            )
            .set_anonymous_client()
            .request_async(&http_client)
            .await
            .unwrap();

        let credential_configuration = &targeted_credentials[0].1;
        let (format, params) = match &credential_configuration.format {
            StandardCredentialFormatMetadata::W3c(format) => match &format.id {
                W3cVcFormat::LdpVc => {
                    let credential_definition = W3cVcDefinitionRequest::default()
                        .with_contexts(format.credential_definition.context.iter().cloned())
                        .with_types(format.credential_definition.r#type.iter().cloned());

                    (
                        W3cVcFormat::LdpVc,
                        W3cVcRequestParams {
                            credential_definition,
                        },
                    )
                }
                W3cVcFormat::JwtVcJsonLd => {
                    let credential_definition = W3cVcDefinitionRequest::default()
                        .with_contexts(format.credential_definition.context.iter().cloned())
                        .with_types(format.credential_definition.r#type.iter().cloned());

                    (
                        W3cVcFormat::JwtVcJsonLd,
                        W3cVcRequestParams {
                            credential_definition,
                        },
                    )
                }
                x => unimplemented!("{x:?}"),
            },
            _ => unimplemented!(),
        };

        let credential_response = client
            .request_credential(
                token_response.access_token().clone(),
                CredentialFormatOrIdentifier::Format(StandardFormat::W3c(format)),
                StandardCredentialRequestParams {
                    w3c_vc: Some(params),
                    ..Default::default()
                },
            )
            .request_async(&http_client)
            .await
            .unwrap();

        println!("{credential_response:?}")
    }
}
