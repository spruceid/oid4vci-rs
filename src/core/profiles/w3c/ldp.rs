use serde::{Deserialize, Serialize};
use ssi_claims::{
    data_integrity::{AnySuite, DataIntegrity},
    vc::AnyJsonCredential,
};

use crate::profiles::{
    AuthorizationDetailsProfile, CredentialConfigurationProfile, CredentialOfferProfile,
    CredentialRequestProfile, CredentialResponseProfile,
};

use super::{CredentialDefinitionLD, CredentialOfferDefinitionLD};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Configuration {
    credential_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(rename = "@context")]
    context: Vec<serde_json::Value>,
    credential_definition: CredentialDefinitionLD,
    order: Option<Vec<String>>,
}

impl Configuration {
    pub fn new(
        context: Vec<serde_json::Value>,
        credential_definition: CredentialDefinitionLD,
    ) -> Self {
        Self {
            credential_signing_alg_values_supported: None,
            context,
            credential_definition,
            order: None,
        }
    }
    field_getters_setters![
        pub self [self] ["LD VC metadata value"] {
            set_credential_signing_alg_values_supported -> credential_signing_alg_values_supported[Option<Vec<String>>],
            set_context -> context[Vec<serde_json::Value>],
            set_credential_definition -> credential_definition[CredentialDefinitionLD],
            set_order -> order[Option<Vec<String>>],
        }
    ];
}
impl CredentialConfigurationProfile for Configuration {
    type Request = Request;

    fn to_request(&self) -> Self::Request {
        Request::new(self.credential_definition().clone())
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
        pub self [self] ["LD VC credential offer value"] {
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
        rename = "credential_configuration_id"
    )]
    _credential_configuration_id: (),
}

impl AuthorizationDetails {
    pub fn new(credential_definition: CredentialDefinitionLD) -> Self {
        Self {
            credential_definition,
            _credential_configuration_id: (),
        }
    }

    field_getters_setters![
        pub self [self] ["LD VC authorization details value"] {
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
        pub self [self] ["LD VC credential request value"] {
            set_credential_definition -> credential_definition[CredentialDefinitionLD],
        }
    ];
}
impl CredentialRequestProfile for Request {
    type Response = Response;
}

// TODO We want to make the credential type generic and avoid using AnySuite, but right now we are already pulling ssi-claims
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Response {
    credential: DataIntegrity<AnyJsonCredential, AnySuite>,
}

impl Response {
    pub fn new(credential: DataIntegrity<AnyJsonCredential, AnySuite>) -> Self {
        Self { credential }
    }

    field_getters_setters![
        pub self [self] ["LD VC credential response value"] {
            set_credential -> credential[DataIntegrity<AnyJsonCredential, AnySuite>],
        }
    ];
}
impl CredentialResponseProfile for Response {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn example_metadata() {
        let _: Configuration = serde_json::from_value(json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": [
                "VerifiableCredential",
                "UniversityDegreeCredential"
            ],
            "credential_definition": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ],
                "credentialSubject": {
                    "given_name": {
                        "display": [
                            {
                                "name": "Given Name",
                                "locale": "en-US"
                            }
                        ]
                    },
                    "family_name": {
                        "display": [
                            {
                                "name": "Surname",
                                "locale": "en-US"
                            }
                        ]
                    },
                    "degree": {},
                    "gpa": {
                        "display": [
                            {
                                "name": "GPA"
                            }
                        ]
                    }
                }
            },
        }))
        .unwrap();
    }

    #[test]
    fn example_offer() {
        let _: Offer = serde_json::from_value(json!({
            "credential_definition": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ]
            }
        }))
        .unwrap();
    }

    #[test]
    fn example_authorization() {
        let _: AuthorizationDetails = serde_json::from_value(json!({
            "credential_definition": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ],
                "credentialSubject": {
                    "given_name": {},
                    "family_name": {},
                    "degree": {}
                }
            }
        }))
        .unwrap();
    }

    #[test]
    fn example_request() {
        let _: Request = serde_json::from_value(json!({
           "credential_definition": {
              "@context": [
                 "https://www.w3.org/2018/credentials/v1",
                 "https://www.w3.org/2018/credentials/examples/v1"
              ],
              "type": [
                 "VerifiableCredential",
                 "UniversityDegreeCredential"
              ],
              "credentialSubject": {
                 "degree": {
                    "type": {}
                 }
              }
           },
        }))
        .unwrap();
    }
}
