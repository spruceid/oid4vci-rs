pub mod profiles;

pub mod metadata {
    use super::profiles::CoreProfilesCredentialConfiguration;

    pub type CredentialIssuerMetadata =
        crate::issuer::CredentialIssuerMetadata<CoreProfilesCredentialConfiguration>;
}

pub mod credential {
    use super::profiles::CoreProfilesCredentialRequest;

    pub type Request = crate::request::CredentialRequest<CoreProfilesCredentialRequest>;
    pub type BatchRequest =
        crate::batch::request::BatchCredentialRequest<CoreProfilesCredentialRequest>;
}

pub mod authorization {
    use crate::authorization;

    use super::profiles::CoreProfilesAuthorizationDetailsObject;

    pub type AuthorizationDetailsObject =
        authorization::AuthorizationDetailsObject<CoreProfilesAuthorizationDetailsObject>;
}

pub mod client {

    use crate::client;

    use super::profiles::CoreProfiles;

    pub type Client = client::Client<CoreProfiles>;
}
