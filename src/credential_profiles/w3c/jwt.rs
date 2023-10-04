use serde::{Deserialize, Serialize};
use ssi::jwk;

use crate::{
    credential_profiles::{
        AuthorizationDetaislProfile, CredentialMetadataProfile, CredentialOfferProfile,
        CredentialRequestProfile, CredentialResponseProfile,
    },
    field_getters, field_getters_setters, field_setters,
};

use super::{CredentialDefinition, CredentialOfferDefinition};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Metadata {
    cryptographic_suites_supported: Option<Vec<jwk::Algorithm>>,
    credential_definition: CredentialDefinition,
    order: Option<Vec<String>>,
}

impl Metadata {
    pub fn new(credential_definition: CredentialDefinition) -> Self {
        Self {
            cryptographic_suites_supported: None,
            credential_definition,
            order: None,
        }
    }

    field_getters_setters![
        pub self [self] ["LD VC metadata value"] {
            set_cryptographic_suites_supported -> cryptographic_suites_supported[Option<Vec<jwk::Algorithm>>],
            set_credential_definition -> credential_definition[CredentialDefinition],
            set_order -> order[Option<Vec<String>>],
        }
    ];
}
impl CredentialMetadataProfile for Metadata {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Offer {
    credential_definition: CredentialOfferDefinition,
}
impl CredentialOfferProfile for Offer {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetails {
    credential_definition: CredentialDefinition,
}

impl AuthorizationDetails {
    pub fn new(credential_definition: CredentialDefinition) -> Self {
        Self {
            credential_definition,
        }
    }
}
impl AuthorizationDetaislProfile for AuthorizationDetails {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request {
    credential_definition: CredentialDefinition,
}
impl CredentialRequestProfile for Request {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Response {
    credential: String,
}
impl CredentialResponseProfile for Response {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn example_metadata() {
        let _: Metadata = serde_json::from_value(json!({
            "credential_definition":{
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
}
