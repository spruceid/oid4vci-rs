pub mod profiles;

pub mod metadata {
    use super::profiles::CustomProfilesCredentialConfiguration;

    pub type CredentialIssuerMetadata =
        crate::issuer::CredentialIssuerMetadata<CustomProfilesCredentialConfiguration>;
}

pub mod credential {
    use super::profiles::CustomProfilesCredentialRequest;

    pub type Request = crate::request::Request<CustomProfilesCredentialRequest>;
    pub type BatchRequest = crate::batch::request::BatchRequest<CustomProfilesCredentialRequest>;
}

pub mod authorization {
    use crate::authorization;

    use super::profiles::CustomProfilesAuthorizationDetailsObject;

    pub type AuthorizationDetailsObject =
        authorization::AuthorizationDetailsObject<CustomProfilesAuthorizationDetailsObject>;
}

pub mod client {

    use crate::client;

    use super::profiles::CustomProfiles;

    pub type Client = client::Client<CustomProfiles>;
}
