pub mod metadata {
    use openidconnect::core::{
        CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    };

    use crate::{credential_profiles::CoreProfilesMetadata, metadata};

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

    use crate::{credential, credential_profiles::CoreProfilesRequest};

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
    use crate::{authorization, credential_profiles::CoreProfilesAuthorizationDetails};

    pub type AuthorizationDetail =
        authorization::AuthorizationDetail<CoreProfilesAuthorizationDetails>;
}

pub mod client {
    use openidconnect::core::{
        CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    };

    use crate::{client, credential_profiles::CoreProfiles};

    pub type Client = client::Client<
        CoreProfiles,
        CoreJsonWebKeyType,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
    >;
}
