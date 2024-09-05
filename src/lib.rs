#[macro_use]
mod macros;

pub mod authorization;
pub mod client;
pub mod core;
pub mod credential;
pub mod credential_offer;
pub mod credential_response_encryption;
mod deny_field;
mod http_utils;
pub mod metadata;
pub mod notification;
pub mod pre_authorized_code;
pub mod profiles;
pub mod proof_of_possession;
pub mod pushed_authorization;
pub mod token;
mod types;

pub use oauth2;

#[cfg(test)]
mod test {
    use crate::core::profiles::ldp_vc::{
        authorization_detail::CredentialDefinition,
        CredentialRequestWithFormat as LdpVcCredentialRequest,
    };
    use crate::core::profiles::{
        CoreProfilesCredentialConfiguration, CoreProfilesCredentialRequest,
        CredentialRequestWithFormat,
    };
    use crate::core::{client::Client, metadata::CredentialIssuerMetadata};
    use crate::credential_offer::CredentialOffer;
    use crate::metadata::authorization_server::GrantType;
    use crate::metadata::credential_issuer::CredentialConfiguration;
    use crate::metadata::{AuthorizationServerMetadata, MetadataDiscovery};
    use crate::types::CredentialOfferRequest;
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

        let credential_issuer_metadata =
            CredentialIssuerMetadata::discover_async(credential_offer.issuer(), &http_client)
                .await
                .unwrap();

        let targeted_credentials: Vec<
            CredentialConfiguration<CoreProfilesCredentialConfiguration>,
        > = credential_issuer_metadata
            .credential_configurations_supported()
            .iter()
            .filter(|configuration| {
                credential_offer
                    .credential_configuration_ids()
                    .contains(configuration.id())
            })
            .cloned()
            .collect();

        assert_eq!(targeted_credentials.len(), 1);

        let grant = credential_offer.pre_authorized_code_grant().unwrap();
        let authorization_server = grant.authorization_server();

        let authorization_server_metadata =
            AuthorizationServerMetadata::discover_from_credential_issuer_metadata_async(
                &http_client,
                &credential_issuer_metadata,
                Some(&GrantType::PreAuthorizedCode),
                authorization_server,
            )
            .await
            .unwrap();

        let client = Client::from_issuer_metadata(
            ClientId::new("test".to_owned()),
            RedirectUrl::new("test://".to_owned()).unwrap(),
            credential_issuer_metadata,
            authorization_server_metadata,
        );

        let token_response = client
            .exchange_pre_authorized_code(
                credential_offer
                    .pre_authorized_code_grant()
                    .unwrap()
                    .pre_authorized_code()
                    .clone(),
            )
            .set_anonymous_client()
            .request_async(&http_client)
            .await
            .unwrap();

        let credential_configuration = &targeted_credentials[0];
        let request_inner = match credential_configuration.profile_specific_fields() {
            CoreProfilesCredentialConfiguration::LdpVc(config) => {
                let credential_definition = CredentialDefinition::default()
                    .set_context(config.credential_definition().context().clone())
                    .set_type(config.credential_definition().r#type().clone());
                CredentialRequestWithFormat::LdpVc(LdpVcCredentialRequest::new(
                    credential_definition,
                ))
            }
            x => unimplemented!("{x:?}"),
        };

        let credential_response = client
            .request_credential(
                token_response.access_token().clone(),
                CoreProfilesCredentialRequest::WithFormat {
                    inner: request_inner,
                    _credential_identifier: (),
                },
            )
            .request_async(&http_client)
            .await
            .unwrap();

        println!("{credential_response:?}")
    }
}
