use serde::{Deserialize, Serialize};

use crate::profiles::{
    AuthorizationDetailsProfile, CredentialConfigurationProfile, CredentialOfferProfile,
    CredentialRequestProfile, CredentialResponseProfile,
};

use super::{CredentialDefinitionLD, CredentialOfferDefinitionLD};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Configuration {
    credential_definition: CredentialDefinitionLD,
}

impl Configuration {
    pub fn new(credential_definition: CredentialDefinitionLD) -> Self {
        Self {
            credential_definition,
        }
    }

    field_getters_setters![
        pub self [self] ["JWT VC LD metadata value"] {
            set_credential_definition -> credential_definition[CredentialDefinitionLD],
        }
    ];
}

impl CredentialConfigurationProfile for Configuration {
    type Request = Request;

    fn to_request(&self) -> Self::Request {
        Request::new(self.credential_definition.clone())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Offer {
    credential_definition: CredentialOfferDefinitionLD,
}

impl Offer {
    pub fn new(credential_definition: CredentialOfferDefinitionLD) -> Self {
        Self {
            credential_definition,
        }
    }

    field_getters_setters![
        pub self [self] ["JWT VC LD offer value"] {
            set_credential_definition -> credential_definition[CredentialOfferDefinitionLD],
        }
    ];
}
impl CredentialOfferProfile for Offer {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetails {
    credential_definition: CredentialDefinitionLD,

    #[serde(
        default,
        skip_serializing,
        deserialize_with = "crate::deny_field::deny_field",
        rename = "credential_identifier"
    )]
    _credential_identifier: (),
}

impl AuthorizationDetails {
    pub fn new(credential_definition: CredentialDefinitionLD) -> Self {
        Self {
            credential_definition,
            _credential_identifier: (),
        }
    }
    field_getters_setters![
        pub self [self] ["JWT VC LD authorization value"] {
            set_credential_definition -> credential_definition[CredentialDefinitionLD],
        }
    ];
}
impl AuthorizationDetailsProfile for AuthorizationDetails {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request {
    credential_definition: CredentialDefinitionLD,

    #[serde(
        default,
        skip_serializing,
        deserialize_with = "crate::deny_field::deny_field",
        rename = "credential_identifier"
    )]
    _credential_identifier: (),
}

impl Request {
    pub fn new(credential_definition: CredentialDefinitionLD) -> Self {
        Self {
            credential_definition,
            _credential_identifier: (),
        }
    }

    field_getters_setters![
        pub self [self] ["JWT VC request value"] {
            set_credential_definition -> credential_definition[CredentialDefinitionLD],
        }
    ];
}
impl CredentialRequestProfile for Request {
    type Response = Response;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Response {
    credential: String,
}

impl Response {
    pub fn new(credential: String) -> Self {
        Self { credential }
    }
    field_getters_setters![
        pub self [self] ["JWT VC response value"] {
            set_credential -> credential[String],
        }
    ];
}
impl CredentialResponseProfile for Response {}
