use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};

pub trait Profile {
    type Metadata: CredentialMetadataProfile;
    type Offer: CredentialOfferProfile;
    type Authorization: AuthorizationDetaislProfile;
    type Credential: CredentialRequestProfile;
}
pub trait CredentialMetadataProfile: Clone + Debug + DeserializeOwned + Serialize {
    type Request: CredentialRequestProfile;

    fn to_request(&self) -> Self::Request;
}
pub trait CredentialOfferProfile: Debug + DeserializeOwned + Serialize {}
pub trait AuthorizationDetaislProfile: Debug + DeserializeOwned + Serialize {}
pub trait CredentialRequestProfile: Debug + DeserializeOwned + Serialize {
    type Response: CredentialResponseProfile;
}
pub trait CredentialResponseProfile: Debug + DeserializeOwned + Serialize {}
