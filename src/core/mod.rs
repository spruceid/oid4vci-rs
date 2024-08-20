pub mod profiles;

pub mod metadata {
    use openidconnect::core::{CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm};

    use crate::metadata;

    use super::profiles::CoreProfilesMetadata;

    pub type CredentialIssuerMetadata = metadata::CredentialIssuerMetadata<
        CoreProfilesMetadata,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
    >;
}

pub mod credential {
    use openidconnect::core::{CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm};

    use crate::credential;

    use super::profiles::CoreProfilesRequest;

    pub type Request = credential::Request<
        CoreProfilesRequest,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
    >;
    pub type BatchRequest = credential::BatchRequest<
        CoreProfilesRequest,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
    >;
}

pub mod authorization {
    use crate::authorization;

    use super::profiles::CoreProfilesAuthorizationDetails;

    pub type AuthorizationDetail =
        authorization::AuthorizationDetail<CoreProfilesAuthorizationDetails>;
}

pub mod client {
    use openidconnect::core::{CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm};

    use crate::client;

    use super::profiles::CoreProfiles;

    pub type Client = client::Client<
        CoreProfiles,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
    >;
}

#[cfg(test)]
mod test {
    use openidconnect::IssuerUrl;
    use profiles::w3c::{self, ldp::CredentialDefinitionLD};

    use crate::{credential_response_encryption::CredentialUrl, metadata::CredentialMetadata};

    use super::*;

    #[test]
    fn serialize_issuer_metadata_jwtvc() {
        let metadata = super::metadata::CredentialIssuerMetadata::new(
            IssuerUrl::from_url("https://example.com".parse().unwrap()),
            CredentialUrl::from_url("https://example.com/credential".parse().unwrap()),
            vec![CredentialMetadata::new(
                "credential1".into(),
                profiles::CoreProfilesMetadata::JWTVC(w3c::jwt::Metadata::new(
                    w3c::CredentialDefinition::new(vec!["type1".into()]),
                )),
            )],
        );
        serde_json::to_vec(&metadata).unwrap();
    }

    #[test]
    fn serialize_issuer_metadata_ldpvc() {
        let metadata = super::metadata::CredentialIssuerMetadata::new(
            IssuerUrl::from_url("https://example.com".parse().unwrap()),
            CredentialUrl::from_url("https://example.com/credential".parse().unwrap()),
            vec![CredentialMetadata::new(
                "credential1".into(),
                profiles::CoreProfilesMetadata::LDVC(w3c::ldp::Metadata::new(
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
            )],
        );
        serde_json::to_vec(&metadata).unwrap();
    }
}
