use std::collections::HashMap;

use isomdl::definitions::device_request::DocType;
use serde::{Deserialize, Serialize};

use super::{
    w3c::CredentialSubjectClaims, AuthorizationDetailsProfile, CredentialMetadataProfile,
    CredentialOfferProfile, CredentialRequestProfile, CredentialResponseProfile,
};

pub type Namespace = String;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Metadata {
    // credential_signing_alg_values_supported: Option<Vec<cose::Algorithm>>, // TODO cose
    doctype: DocType,
    claims: Option<HashMap<Namespace, CredentialSubjectClaims>>,
    order: Option<Vec<String>>,
}

impl Metadata {
    pub fn new(doctype: DocType) -> Self {
        Self {
            doctype,
            claims: None,
            order: None,
        }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL metadata value"] {
            set_doctype -> doctype[DocType],
            set_claims -> claims[Option<HashMap<Namespace, CredentialSubjectClaims>>],
            set_order -> order[Option<Vec<String>>],
        }
    ];
}
impl CredentialMetadataProfile for Metadata {
    type Request = Request;

    fn to_request(&self) -> Self::Request {
        Request::new(self.doctype().clone()).set_claims(self.claims().cloned())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Offer {
    doctype: DocType,
}

impl Offer {
    pub fn new(doctype: DocType) -> Self {
        Self { doctype }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL credential offer value"] {
            set_doctype -> doctype[DocType],
        }
    ];
}
impl CredentialOfferProfile for Offer {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetails {
    doctype: DocType,
    claims: Option<HashMap<Namespace, CredentialSubjectClaims>>,

    #[serde(
        default,
        skip_serializing,
        deserialize_with = "crate::deny_field::deny_field",
        rename = "credential_configuration_id"
    )]
    _credential_configuration_id: (),
}

impl AuthorizationDetails {
    pub fn new(
        doctype: DocType,
        claims: Option<HashMap<Namespace, CredentialSubjectClaims>>,
    ) -> Self {
        Self {
            doctype,
            claims,
            _credential_configuration_id: (),
        }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL authorization details value"] {
            set_doctype -> doctype[DocType],
            set_claims -> claims[Option<HashMap<Namespace, CredentialSubjectClaims>>],
        }
    ];
}
impl AuthorizationDetailsProfile for AuthorizationDetails {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request {
    doctype: DocType,
    claims: Option<HashMap<Namespace, CredentialSubjectClaims>>,

    #[serde(
        default,
        skip_serializing,
        deserialize_with = "crate::deny_field::deny_field",
        rename = "credential_identifier"
    )]
    _credential_identifier: (),
}

impl Request {
    pub fn new(doctype: DocType) -> Self {
        Self {
            doctype,
            claims: None,
            _credential_identifier: (),
        }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL request value"] {
            set_doctype -> doctype[DocType],
            set_claims -> claims[Option<HashMap<Namespace, CredentialSubjectClaims>>],
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
        pub self [self] ["ISO mDL response value"] {
            set_credential -> credential[String],
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
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "org.iso.18013.5.1": {
                    "given_name": {
                        "display": [
                            {
                                "name": "Given Name",
                                "locale": "en-US"
                            },
                            {
                                "name": "名前",
                                "locale": "ja-JP"
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
                    "birth_date": {}
                },
                "org.iso.18013.5.1.aamva": {
                    "organ_donor": {}
                }
            }
        }))
        .unwrap();
    }

    #[test]
    fn example_offer() {
        let _: Offer = serde_json::from_value(json!({
            "doctype": "org.iso.18013.5.1.mDL"
        }))
        .unwrap();
    }

    #[test]
    fn example_authorization() {
        let _: AuthorizationDetails = serde_json::from_value(json!({
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "org.iso.18013.5.1": {
                    "given_name": {},
                    "family_name": {},
                    "birth_date": {}
                },
                "org.iso.18013.5.1.aamva": {
                    "organ_donor": {}
                }
            }
        }))
        .unwrap();
    }

    #[test]
    fn example_request() {
        let _: Request = serde_json::from_value(json!({
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
               "org.iso.18013.5.1": {
                  "given_name": {},
                  "family_name": {},
                  "birth_date": {}
               },
               "org.iso.18013.5.1.aamva": {
                  "organ_donor": {}
               }
            },
        }))
        .unwrap();
    }
}
