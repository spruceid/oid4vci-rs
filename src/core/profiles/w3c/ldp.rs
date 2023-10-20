use serde::{Deserialize, Serialize};
use ssi::{ldp::ProofSuiteType, vc::Credential};

use crate::profiles::{
    AuthorizationDetaislProfile, CredentialMetadataProfile, CredentialOfferProfile,
    CredentialRequestProfile, CredentialResponseProfile,
};

use super::{CredentialDefinition, CredentialOfferDefinition};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Metadata {
    cryptographic_suites_supported: Option<Vec<ProofSuiteType>>,
    #[serde(rename = "@context")]
    context: Vec<serde_json::Value>,
    credentials_definition: CredentialDefinitionLD,
    order: Option<Vec<String>>,
}

impl Metadata {
    pub fn new(
        context: Vec<serde_json::Value>,
        credentials_definition: CredentialDefinitionLD,
    ) -> Self {
        Self {
            cryptographic_suites_supported: None,
            context,
            credentials_definition,
            order: None,
        }
    }
    field_getters_setters![
        pub self [self] ["LD VC metadata value"] {
            set_cryptographic_suites_supported -> cryptographic_suites_supported[Option<Vec<ProofSuiteType>>],
            set_context -> context[Vec<serde_json::Value>],
            set_credentials_definition -> credentials_definition[CredentialDefinitionLD],
            set_order -> order[Option<Vec<String>>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinitionLD {
    #[serde(flatten)]
    credential_definition: CredentialDefinition,
    #[serde(rename = "@context")]
    context: Vec<serde_json::Value>,
}

impl CredentialDefinitionLD {
    pub fn new(
        credential_definition: CredentialDefinition,
        context: Vec<serde_json::Value>,
    ) -> Self {
        Self {
            credential_definition,
            context,
        }
    }
    field_getters_setters![
        pub self [self] ["LD VC credential definition value"] {
            set_credential_definition -> credential_definition[CredentialDefinition],
            set_context -> context[Vec<serde_json::Value>],
        }
    ];
}
impl CredentialMetadataProfile for Metadata {
    type Request = Request;

    fn to_request(&self) -> Self::Request {
        Request::new(self.credentials_definition().clone())
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
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialOfferDefinitionLD {
    #[serde(rename = "@context")]
    context: Vec<serde_json::Value>,
    #[serde(flatten)]
    credential_offer_definite: CredentialOfferDefinition,
}

impl CredentialOfferDefinitionLD {
    pub fn new(
        context: Vec<serde_json::Value>,
        credential_offer_definite: CredentialOfferDefinition,
    ) -> Self {
        Self {
            context,
            credential_offer_definite,
        }
    }

    field_getters_setters![
        pub self [self] ["LD VC credential offer definition value"] {
            set_context -> context[Vec<serde_json::Value>],
            set_credential_offer_definite -> credential_offer_definite[CredentialOfferDefinition],
        }
    ];
}
impl CredentialOfferProfile for Offer {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetails {
    credential_definition: CredentialDefinitionLD,
}

impl AuthorizationDetails {
    pub fn new(credential_definition: CredentialDefinitionLD) -> Self {
        Self {
            credential_definition,
        }
    }

    field_getters_setters![
        pub self [self] ["LD VC authorization details value"] {
            set_credential_definition -> credential_definition[CredentialDefinitionLD],
        }
    ];
}
impl AuthorizationDetaislProfile for AuthorizationDetails {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request {
    credential_definition: CredentialDefinitionLD,
}

impl Request {
    pub fn new(credential_definition: CredentialDefinitionLD) -> Self {
        Self {
            credential_definition,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Response {
    credential: Credential,
}

impl Response {
    pub fn new(credential: Credential) -> Self {
        Self { credential }
    }

    field_getters_setters![
        pub self [self] ["LD VC credential response value"] {
            set_credential -> credential[Credential],
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
        let _: Metadata = serde_json::from_value(json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": [
                "VerifiableCredential",
                "UniversityDegreeCredential"
            ],
            "credentials_definition": {
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
