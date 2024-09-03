use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};

pub trait Profile {
    type Configuration: CredentialConfigurationProfile;
    type Offer: CredentialOfferProfile;
    type Authorization: AuthorizationDetailsProfile;
    type Credential: CredentialRequestProfile;
}
pub trait CredentialConfigurationProfile: Clone + Debug + DeserializeOwned + Serialize {
    type Request: CredentialRequestProfile;

    fn to_request(&self) -> Self::Request;
}
pub trait CredentialOfferProfile: Debug + DeserializeOwned + Serialize {}
pub trait AuthorizationDetailsProfile: Debug + DeserializeOwned + Serialize {}
pub trait CredentialRequestProfile: Clone + Debug + DeserializeOwned + Serialize {
    type Response: CredentialResponseProfile;
}
pub trait CredentialResponseProfile: Debug + DeserializeOwned + Serialize {}
