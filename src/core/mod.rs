pub mod profiles;

pub mod metadata {
    use crate::metadata;

    use super::profiles::CoreProfilesCredentialConfiguration;

    pub type CredentialIssuerMetadata =
        metadata::CredentialIssuerMetadata<CoreProfilesCredentialConfiguration>;
}

pub mod credential {
    use crate::credential;

    use super::profiles::CoreProfilesCredentialRequest;

    pub type Request = credential::Request<CoreProfilesCredentialRequest>;
    pub type BatchRequest = credential::BatchRequest<CoreProfilesCredentialRequest>;
}

pub mod authorization {
    use crate::authorization;

    use super::profiles::CoreProfilesAuthorizationDetail;

    pub type AuthorizationDetail =
        authorization::AuthorizationDetail<CoreProfilesAuthorizationDetail>;
}

pub mod client {

    use crate::client;

    use super::profiles::CoreProfiles;

    pub type Client = client::Client<CoreProfiles>;
}
