use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::authorization::CredentialAuthorizationParams;

use super::{W3cClaimRequest, W3cVcFormat};

#[skip_serializing_none]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct W3cVcAuthorizationParams {
    pub credential_definition: Option<W3cVcDefinitionAuthorization>,
}

impl CredentialAuthorizationParams for W3cVcAuthorizationParams {
    type Format = W3cVcFormat;
}

#[skip_serializing_none]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct W3cVcDefinitionAuthorization {
    #[serde(rename = "@context")]
    pub context: Option<Vec<ssi::json_ld::syntax::ContextEntry>>,

    pub r#type: Option<Vec<String>>,

    #[serde(
        rename = "credentialSubject",
        skip_serializing_if = "IndexMap::is_empty"
    )]
    pub credential_subject: IndexMap<String, W3cClaimRequest>,
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
                "type": "openid_credential",
                "format": "jwt_vc_json",
                "credential_definition": {
                    "type": ["UniversityDegreeCredential"],
                    "credentialSubject": {
                        "given_name": {},
                        "family_name": {},
                        "degree": {}
                    }
                }
            }
        );

        let authorization_detail: CredentialAuthorizationDetailsObject<W3cVcAuthorizationParams> =
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
                "type": "openid_credential",
                "credential_configuration_id": "UniversityDegreeCredential",
                "credential_definition": {
                    "credentialSubject": {
                        "given_name": {},
                        "family_name": {},
                        "degree": {}
                    }
                }
            }
        );

        let authorization_detail: CredentialAuthorizationDetailsObject<W3cVcAuthorizationParams> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(authorization_detail).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
