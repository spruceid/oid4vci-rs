use std::collections::HashMap;

use isomdl::definitions::device_request::DocType;
use serde::{Deserialize, Serialize};

use super::{
    w3c::CredentialSubjectClaims, AuthorizationDetaislProfile, CredentialMetadataProfile,
    CredentialOfferProfile, CredentialRequestProfile, CredentialResponseProfile,
};

pub type Namespace = String;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Metadata {
    // cryptographic_suites_supported: Option<Vec<cose::Algorithm>>, // TODO cose
    doctype: DocType,
    claims: Option<HashMap<Namespace, CredentialSubjectClaims>>,
    order: Option<Vec<String>>,
}
impl CredentialMetadataProfile for Metadata {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Offer {
    doctype: DocType,
}
impl CredentialOfferProfile for Offer {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetails {
    doctype: DocType,
    claims: Option<HashMap<Namespace, CredentialSubjectClaims>>,
}
impl AuthorizationDetaislProfile for AuthorizationDetails {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Request {
    doctype: DocType,
    claims: Option<HashMap<Namespace, CredentialSubjectClaims>>,
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
