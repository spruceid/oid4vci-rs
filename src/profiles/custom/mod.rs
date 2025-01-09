pub mod profiles;

pub mod metadata {
    use crate::metadata;

    use super::profiles::CustomProfilesCredentialConfiguration;

    pub type CredentialIssuerMetadata =
        metadata::CredentialIssuerMetadata<CustomProfilesCredentialConfiguration>;
}

pub mod credential {
    use crate::credential;

    use super::profiles::CustomProfilesCredentialRequest;

    pub type Request = credential::Request<CustomProfilesCredentialRequest>;
    pub type BatchRequest = credential::BatchRequest<CustomProfilesCredentialRequest>;
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
