use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::request::CredentialRequestParams;

use super::{MsoMdocClaimMetadata, MsoMdocFormat};

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsoMdocRequestParams {
    pub doctype: Option<String>,

    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub claims: IndexMap<String, IndexMap<String, MsoMdocClaimMetadata>>,
}

impl CredentialRequestParams for MsoMdocRequestParams {
    type Format = MsoMdocFormat;
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::request::CredentialRequest;

    use super::*;

    #[test]
    fn roundtrip_with_format() {
        let expected_json = json!(
            {
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
                },
                "proof": {
                   "proof_type": "jwt",
                   "jwt": "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM"
                }
            }
        );

        let credential_request: CredentialRequest<MsoMdocRequestParams> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_request).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped);
    }

    #[test]
    fn roundtrip() {
        let expected_json = json!(
            {
                "credential_identifier": "org.iso.18013.5.1.mDL",
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
                "proof": {
                   "proof_type": "jwt",
                   "jwt": "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM"
                }
            }
        );

        let credential_request: CredentialRequest<MsoMdocRequestParams> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_request).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped);
    }
}
