use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{core::profiles::AuthorizationDetailClaim, profiles::AuthorizationDetailProfile};

use super::{CredentialSubjectClaims, Format};

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailWithFormat {
    format: Format,
    credential_definition: CredentialDefinition,
}

impl AuthorizationDetailWithFormat {
    field_getters_setters![
        pub self [self] ["JWT VC authorization detail value"] {
            set_credential_definition -> credential_definition[CredentialDefinition],
        }
    ];
}

impl AuthorizationDetailProfile for AuthorizationDetailWithFormat {}

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetail {
    credential_definition: CredentialDefinitionWithoutType,
}

impl AuthorizationDetail {
    field_getters_setters![
        pub self [self] ["JWT VC authorization detail value"] {
            set_credential_definition -> credential_definition[CredentialDefinitionWithoutType],
        }
    ];
}

impl AuthorizationDetailProfile for AuthorizationDetail {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinition {
    r#type: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        rename = "credentialSubject"
    )]
    credential_subject: CredentialSubjectClaims<AuthorizationDetailClaim>,
}

impl CredentialDefinition {
    field_getters_setters![
        pub self [self] ["credential definition value"] {
            set_type -> r#type[Vec<String>],
            set_credential_subject -> credential_subject[CredentialSubjectClaims<AuthorizationDetailClaim>],
        }
    ];
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinitionWithoutType {
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        rename = "credentialSubject"
    )]
    credential_subject: CredentialSubjectClaims<AuthorizationDetailClaim>,
}

impl CredentialDefinitionWithoutType {
    field_getters_setters![
        pub self [self] ["credential definition value"] {
            set_credential_subject -> credential_subject[CredentialSubjectClaims<AuthorizationDetailClaim>],
        }
    ];
}

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

        let authorization_detail: AuthorizationDetail<CoreProfilesAuthorizationDetail> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(authorization_detail).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
