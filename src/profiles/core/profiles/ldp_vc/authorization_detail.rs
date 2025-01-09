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
    format: F,
    credential_definition: CredentialDefinition,
}

impl<F> AuthorizationDetailsObjectWithFormat<F> {
    field_getters_setters![
        pub self [self] ["authorization detail value"] {
            set_credential_definition -> credential_definition[CredentialDefinition],
        }
    ];
}

impl<F> AuthorizationDetailsObjectProfile for AuthorizationDetailsObjectWithFormat<F> where
    F: DeserializeOwned + Serialize + Debug + Clone
{
}

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObject {
    credential_definition: CredentialDefinitionWithoutContext,
}

impl AuthorizationDetailsObject {
    field_getters_setters![
        pub self [self] ["authorization detail value"] {
            set_credential_definition -> credential_definition[CredentialDefinitionWithoutContext],
        }
    ];
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObject {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinition {
    #[serde(rename = "@context")]
    context: Vec<Value>,
    r#type: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        rename = "credentialSubject"
    )]
    credential_subject: CredentialSubjectClaims<AuthorizationDetailsObjectClaim>,
}

impl CredentialDefinition {
    field_getters_setters![
        pub self [self] ["credential definition value"] {
            set_context -> context[Vec<Value>],
            set_type -> r#type[Vec<String>],
            set_credential_subject -> credential_subject[CredentialSubjectClaims<AuthorizationDetailsObjectClaim>],
        }
    ];
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialDefinitionWithoutContext {
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        rename = "credentialSubject"
    )]
    credential_subject: CredentialSubjectClaims<AuthorizationDetailsObjectClaim>,
}

impl CredentialDefinitionWithoutContext {
    field_getters_setters![
        pub self [self] ["credential definition value"] {
            set_credential_subject -> credential_subject[CredentialSubjectClaims<AuthorizationDetailsObjectClaim>],
        }
    ];
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
