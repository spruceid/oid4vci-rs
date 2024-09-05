use isomdl::definitions::device_request::DocType;
use serde::{Deserialize, Serialize};

use crate::{core::profiles::CredentialConfigurationClaim, profiles::CredentialRequestProfile};

use super::{Claims, Format};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialRequestWithFormat {
    format: Format,
    doctype: DocType,
    // Possibly the spec needs updating, `display` and `value_type` don't seem to have any use
    // here.
    #[serde(default, skip_serializing_if = "Claims::is_empty")]
    claims: Claims<CredentialConfigurationClaim>,
}

impl CredentialRequestWithFormat {
    pub fn new(doctype: DocType) -> Self {
        Self {
            format: Format::MsoMdoc,
            doctype,
            claims: Claims::new(),
        }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL request value"] {
            set_doctype -> doctype[DocType],
            set_claims -> claims[Claims<CredentialConfigurationClaim>],
        }
    ];
}

impl CredentialRequestProfile for CredentialRequestWithFormat {
    type Response = super::CredentialResponse;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialRequest {
    // Possibly the spec needs updating, `display` and `value_type` don't seem to have any use
    // here.
    #[serde(default, skip_serializing_if = "Claims::is_empty")]
    claims: Claims<CredentialConfigurationClaim>,
}

impl Default for CredentialRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialRequest {
    pub fn new() -> Self {
        Self {
            claims: Claims::new(),
        }
    }
    field_getters_setters![
        pub self [self] ["ISO mDL request value"] {
            set_claims -> claims[Claims<CredentialConfigurationClaim>],
        }
    ];
}

impl CredentialRequestProfile for CredentialRequest {
    type Response = super::CredentialResponse;
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::{core::profiles::CoreProfilesCredentialRequest, credential::Request};

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

        let credential_request: Request<super::CredentialRequestWithFormat> =
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

        let credential_request: Request<CoreProfilesCredentialRequest> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_request).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped);
    }
}
