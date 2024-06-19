use serde::{Deserialize, Serialize};
use ssi_claims::CompactJWSString;

use crate::profiles::{
    AuthorizationDetaislProfile, CredentialMetadataProfile, CredentialOfferProfile,
    CredentialRequestProfile, CredentialResponseProfile,
};

use super::{CredentialDefinition, CredentialOfferDefinition};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Metadata {
    cryptographic_suites_supported: Option<Vec<ssi_jwk::Algorithm>>,
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
        pub self [self] ["JWT VC metadata value"] {
            set_cryptographic_suites_supported -> cryptographic_suites_supported[Option<Vec<ssi_jwk::Algorithm>>],
            set_credential_definition -> credential_definition[CredentialDefinition],
            set_order -> order[Option<Vec<String>>],
        }
    ];
}
impl CredentialMetadataProfile for Metadata {
    type Request = Request;

    fn to_request(&self) -> Self::Request {
        Request::new(self.credential_definition().clone())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Offer {
    credential_definition: CredentialOfferDefinition,
}

impl Offer {
    pub fn new(credential_definition: CredentialOfferDefinition) -> Self {
        Self {
            credential_definition,
        }
    }
    field_getters_setters![
        pub self [self] ["JWT VC offer value"] {
            set_credential_definition -> credential_definition[CredentialOfferDefinition],
        }
    ];
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
    field_getters_setters![
        pub self [self] ["JWT VC authorization value"] {
            set_credential_definition -> credential_definition[CredentialDefinition],
        }
    ];
}
impl AuthorizationDetaislProfile for AuthorizationDetails {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request {
    credential_definition: CredentialDefinition,
}

impl Request {
    pub fn new(credential_definition: CredentialDefinition) -> Self {
        Self {
            credential_definition,
        }
    }
    field_getters_setters![
        pub self [self] ["JWT VC request value"] {
            set_credential_definition -> credential_definition[CredentialDefinition],
        }
    ];
}
impl CredentialRequestProfile for Request {
    type Response = Response;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Response {
    credential: CompactJWSString,
}

impl Response {
    pub fn new(credential: CompactJWSString) -> Self {
        Self { credential }
    }
    field_getters_setters![
        pub self [self] ["JWT VC response value"] {
            set_credential -> credential[CompactJWSString],
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
