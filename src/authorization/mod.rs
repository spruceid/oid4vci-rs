pub mod authorization_details;
pub mod issuer_state;
pub mod oauth2;
pub mod server;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::authorization::authorization_details::{
        AnyCredentialAuthorizationParams, CredentialAuthorizationDetailsRequest,
    };

    #[test]
    fn example_authorization_details_credential_configuration_id() {
        let _: Vec<CredentialAuthorizationDetailsRequest<AnyCredentialAuthorizationParams>> =
            serde_json::from_value(json!([
                {
                  "type": "openid_credential",
                  "credential_configuration_id": "UniversityDegreeCredential"
                }
            ]))
            .unwrap();
    }

    #[test]
    fn example_authorization_details_locations() {
        let _: Vec<CredentialAuthorizationDetailsRequest<AnyCredentialAuthorizationParams>> =
            serde_json::from_value(json!([
                {
                  "type": "openid_credential",
                  "credential_configuration_id": "id",
                  "locations": [
                     "https://credential-issuer.example.com"
                  ]
               }
            ]))
            .unwrap();
    }

    #[test]
    fn example_authorization_details_multiple() {
        let _: Vec<CredentialAuthorizationDetailsRequest<AnyCredentialAuthorizationParams>> =
            serde_json::from_value(json!([
                {
                  "type": "openid_credential",
                  "credential_configuration_id": "foo"
               },
               {
                  "type": "openid_credential",
                  "credential_configuration_id": "bar"
               }
            ]))
            .unwrap();
    }
}
