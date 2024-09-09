use std::collections::HashMap;

use isomdl::definitions::device_request::DocType;
use serde::{Deserialize, Serialize};

use crate::{
    core::profiles::AuthorizationDetailsObjectClaim, profiles::AuthorizationDetailsObjectProfile,
};

use super::{Claims, Format};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetailsObjectWithFormat {
    format: Format,
    doctype: DocType,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    claims: Claims<AuthorizationDetailsObjectClaim>,
}

impl AuthorizationDetailsObjectWithFormat {
    pub fn new(doctype: DocType, claims: Claims<AuthorizationDetailsObjectClaim>) -> Self {
        Self {
            format: Format::MsoMdoc,
            doctype,
            claims,
        }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL authorization detail value"] {
            set_doctype -> doctype[DocType],
            set_claims -> claims[Claims<AuthorizationDetailsObjectClaim>],
        }
    ];
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObjectWithFormat {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetailsObject {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    claims: Claims<AuthorizationDetailsObjectClaim>,
}

impl AuthorizationDetailsObject {
    pub fn new(claims: Claims<AuthorizationDetailsObjectClaim>) -> Self {
        Self { claims }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL authorization detail value"] {
            set_claims -> claims[ Claims<AuthorizationDetailsObjectClaim>],
        }
    ];
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObject {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::{
        authorization::AuthorizationDetailsObject,
        core::profiles::CoreProfilesAuthorizationDetailsObject,
    };

    #[test]
    fn roundtrip_with_format() {
        let expected_json = json!(
            {
                "type":"openid_credential",
                "format": "mso_mdoc",
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
            }
        );

        let authorization_detail: AuthorizationDetailsObject<
            super::AuthorizationDetailsObjectWithFormat,
        > = serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
            &serde_json::to_string(&expected_json).unwrap(),
        ))
        .unwrap();

        let roundtripped = serde_json::to_value(authorization_detail).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }

    #[test]
    fn roundtrip() {
        let expected_json = json!(
            {
                "type":"openid_credential",
                "credential_configuration_id": "org.iso.18013.5.1.mDL",
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
            }
        );

        let authorization_detail: AuthorizationDetailsObject<
            CoreProfilesAuthorizationDetailsObject,
        > = serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
            &serde_json::to_string(&expected_json).unwrap(),
        ))
        .unwrap();

        let roundtripped = serde_json::to_value(authorization_detail).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
