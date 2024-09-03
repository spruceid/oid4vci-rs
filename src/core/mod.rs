pub mod profiles;

pub mod metadata {
    use crate::metadata;

    use super::profiles::CoreProfilesConfiguration;

    pub type CredentialIssuerMetadata =
        metadata::CredentialIssuerMetadata<CoreProfilesConfiguration>;
}

pub mod credential {
    use crate::credential;

    use super::profiles::CoreProfilesRequest;

    pub type Request = credential::Request<CoreProfilesRequest>;
    pub type BatchRequest = credential::BatchRequest<CoreProfilesRequest>;
}

pub mod authorization {
    use crate::authorization;

    use super::profiles::CoreProfilesAuthorizationDetails;

    pub type AuthorizationDetail =
        authorization::AuthorizationDetail<CoreProfilesAuthorizationDetails>;
}

pub mod client {

    use crate::client;

    use super::profiles::CoreProfiles;

    pub type Client = client::Client<CoreProfiles>;
}

#[cfg(test)]
mod test {
    use profiles::w3c::{self, CredentialDefinitionLD};

    use crate::{
        credential_response_encryption::CredentialUrl,
        metadata::credential_issuer::CredentialMetadata, types::IssuerUrl,
    };

    use super::*;

    #[test]
    fn serialize_issuer_metadata_jwtvc() {
        let metadata = super::metadata::CredentialIssuerMetadata::new(
            IssuerUrl::from_url("https://example.com".parse().unwrap()),
            CredentialUrl::from_url("https://example.com/credential".parse().unwrap()),
        )
        .set_credential_configurations_supported(vec![CredentialMetadata::new(
            "credential1".into(),
            profiles::CoreProfilesConfiguration::JWTVC(w3c::jwt::Configuration::new(
                w3c::CredentialDefinition::new(vec!["type1".into()]),
            )),
        )]);
        serde_json::to_vec(&metadata).unwrap();
    }

    #[test]
    fn serialize_issuer_metadata_ldpvc() {
        let metadata = super::metadata::CredentialIssuerMetadata::new(
            IssuerUrl::from_url("https://example.com".parse().unwrap()),
            CredentialUrl::from_url("https://example.com/credential".parse().unwrap()),
        )
        .set_credential_configurations_supported(vec![CredentialMetadata::new(
            "credential1".into(),
            profiles::CoreProfilesConfiguration::LDVC(w3c::ldp::Configuration::new(
                vec![serde_json::Value::String(
                    "http://example.com/context".into(),
                )],
                CredentialDefinitionLD::new(
                    w3c::CredentialDefinition::new(vec!["type1".into()]),
                    vec![serde_json::Value::String(
                        "http://example.com/context".into(),
                    )],
                ),
            )),
        )]);
        serde_json::to_vec(&metadata).unwrap();
    }
}
