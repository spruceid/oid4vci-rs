use std::collections::HashMap;
use std::fmt::Debug;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::{
    profiles::core::profiles::AuthorizationDetailsObjectClaim,
    profiles::AuthorizationDetailsObjectProfile,
};

use super::CredentialSubjectClaims;

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObjectWithFormat<F> {
    pub format: F,
    pub credential_definition: CredentialDefinition,
}

impl<F> AuthorizationDetailsObjectProfile for AuthorizationDetailsObjectWithFormat<F> where
    F: DeserializeOwned + Serialize + Debug + Clone
{
}

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObject {
    pub credential_definition: CredentialDefinitionWithoutContext,
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObject {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinition {
    #[serde(rename = "@context")]
    pub context: Vec<Value>,
    pub r#type: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        rename = "credentialSubject"
    )]
    pub credential_subject: CredentialSubjectClaims<AuthorizationDetailsObjectClaim>,
}

impl CredentialDefinition {
    pub fn with_context(self, context: Vec<Value>) -> Self {
        Self { context, ..self }
    }

    pub fn with_type(self, r#type: Vec<String>) -> Self {
        Self { r#type, ..self }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinitionWithoutContext {
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
        profiles::core::profiles::{ldp_vc::Format, CoreProfilesAuthorizationDetailsObject},
    };

    #[test]
    fn roundtrip_with_format() {
        let expected_json = json!(
            {
                "type": "openid_credential",
                "format": "ldp_vc",
                "credential_definition": {
                    "@context": [
                       "https://www.w3.org/2018/credentials/v1",
                       "https://www.w3.org/2018/credentials/examples/v1"
                    ],
                    "type": ["UniversityDegreeCredential_LDP_VC"],
                    "credentialSubject": {
                        "given_name": {},
                        "family_name": {},
                        "degree": {}
                    }
                }
            }
        );

        let authorization_detail: AuthorizationDetailsObject<
            super::AuthorizationDetailsObjectWithFormat<Format>,
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
                "credential_configuration_id": "UniversityDegreeCredential_LDP_VC",
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
