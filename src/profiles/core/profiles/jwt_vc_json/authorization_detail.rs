use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    profiles::core::profiles::AuthorizationDetailsObjectClaim,
    profiles::AuthorizationDetailsObjectProfile,
};

use super::{CredentialSubjectClaims, Format};

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObjectWithFormat {
    pub format: Format,
    pub credential_definition: CredentialDefinition,
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObjectWithFormat {}

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObject {
    pub credential_definition: CredentialDefinitionWithoutType,
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObject {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinition {
    pub r#type: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        rename = "credentialSubject"
    )]
    pub credential_subject: CredentialSubjectClaims<AuthorizationDetailsObjectClaim>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinitionWithoutType {
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        rename = "credentialSubject"
    )]
    pub credential_subject: CredentialSubjectClaims<AuthorizationDetailsObjectClaim>,
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::{
        authorization::AuthorizationDetailsObject,
        profiles::core::profiles::CoreProfilesAuthorizationDetailsObject,
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
