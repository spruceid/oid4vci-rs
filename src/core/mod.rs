pub mod profiles;

pub mod metadata {
    use openidconnect::core::{
        CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    };

    use crate::metadata;

    use super::profiles::CoreProfilesMetadata;

    pub type IssuerMetadata = metadata::IssuerMetadata<
        CoreProfilesMetadata,
        CoreJsonWebKeyType,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
    >;
}

pub mod credential {
    use openidconnect::core::{
        CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    };

    use crate::credential;

    use super::profiles::CoreProfilesRequest;

    pub type Request = credential::Request<
        CoreProfilesRequest,
        CoreJsonWebKeyType,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
    >;
    pub type BatchRequest = credential::BatchRequest<
        CoreProfilesRequest,
        CoreJsonWebKeyType,
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
    use openidconnect::core::{
        CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    };

    use crate::client;

    use super::profiles::CoreProfiles;

    pub type Client = client::Client<
        CoreProfiles,
        CoreJsonWebKeyType,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
    >;
}
