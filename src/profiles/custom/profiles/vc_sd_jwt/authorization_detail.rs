use serde::{Deserialize, Serialize};

use crate::profiles::custom::profiles::{
    AuthorizationDetailsObjectProfile, CredentialConfigurationClaim,
};

use super::{Claims, Format};

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObjectWithFormat {
    pub format: Format,
    pub vct: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Claims<CredentialConfigurationClaim>>,
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObjectWithFormat {}

#[derive(Clone, Debug, Deserialize, Default, PartialEq, Serialize)]
pub struct AuthorizationDetailsObject {
    pub vct: String,
    pub claims: Option<Claims<CredentialConfigurationClaim>>,
}

impl AuthorizationDetailsObjectProfile for AuthorizationDetailsObject {}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::authorization::AuthorizationDetailsObject;

    #[test]
    fn roundtrip_with_format() {
        let expected_json = json!(
            {
                "type": "openid_credential",
                "format": "spruce-vc+sd-jwt",
                "vct": "SD_JWT_VC_example_in_OpenID4VCI"
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
}
