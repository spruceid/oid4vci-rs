use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::authorization::CredentialAuthorizationParams;

use super::MsoMdocFormat;

#[skip_serializing_none]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MsoMdocAuthorizationParams {
    pub doctype: Option<String>,

    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub claims: IndexMap<String, IndexMap<String, MsoMdocClaimAuthorization>>,
}

impl CredentialAuthorizationParams for MsoMdocAuthorizationParams {
    type Format = MsoMdocFormat;
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsoMdocClaimAuthorization {
    #[serde(default, skip_serializing_if = "crate::util::is_false")]
    pub mandatory: bool,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::authorization::CredentialAuthorizationDetailsObject;

    use super::*;

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

        let authorization_detail: CredentialAuthorizationDetailsObject<MsoMdocAuthorizationParams> =
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

        let authorization_detail: CredentialAuthorizationDetailsObject<MsoMdocAuthorizationParams> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(authorization_detail).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
