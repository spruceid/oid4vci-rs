use std::collections::HashMap;

use isomdl::definitions::device_request::DocType;
use serde::{Deserialize, Serialize};

use crate::{core::profiles::AuthorizationDetailClaim, profiles::AuthorizationDetailProfile};

use super::{Claims, Format};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetailWithFormat {
    format: Format,
    doctype: DocType,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    claims: Claims<AuthorizationDetailClaim>,
}

impl AuthorizationDetailWithFormat {
    pub fn new(doctype: DocType, claims: Claims<AuthorizationDetailClaim>) -> Self {
        Self {
            format: Format::MsoMdoc,
            doctype,
            claims,
        }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL authorization detail value"] {
            set_doctype -> doctype[DocType],
            set_claims -> claims[Claims<AuthorizationDetailClaim>],
        }
    ];
}

impl AuthorizationDetailProfile for AuthorizationDetailWithFormat {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetail {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    claims: Claims<AuthorizationDetailClaim>,
}

impl AuthorizationDetail {
    pub fn new(claims: Claims<AuthorizationDetailClaim>) -> Self {
        Self { claims }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL authorization detail value"] {
            set_claims -> claims[ Claims<AuthorizationDetailClaim>],
        }
    ];
}

impl AuthorizationDetailProfile for AuthorizationDetail {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::{
        authorization::AuthorizationDetail, core::profiles::CoreProfilesAuthorizationDetail,
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

        let authorization_detail: AuthorizationDetail<super::AuthorizationDetailWithFormat> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
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

        let authorization_detail: AuthorizationDetail<CoreProfilesAuthorizationDetail> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(authorization_detail).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
