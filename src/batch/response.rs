use serde::{Deserialize, Serialize};

use crate::{profiles::CredentialResponseProfile, response::ResponseEnum, types::Nonce};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchResponse<CR>
where
    CR: CredentialResponseProfile,
{
    #[serde(bound = "CR: CredentialResponseProfile")]
    pub credential_responses: Vec<ResponseEnum<CR>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<Nonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<i64>,
}

impl<CR> BatchResponse<CR>
where
    CR: CredentialResponseProfile,
{
    pub fn new(credential_responses: Vec<ResponseEnum<CR>>) -> Self {
        Self {
            credential_responses,
            c_nonce: None,
            c_nonce_expires_in: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::profiles::core::profiles::CoreProfilesCredentialResponse;

    use super::*;

    #[test]
    fn example_batch_response() {
        let _: BatchResponse<CoreProfilesCredentialResponse> = serde_json::from_value(json!({
            "credential_responses": [{
                "format": "jwt_vc_json",
                "credential": "eyJraWQiOiJkaWQ6ZXhhbXBsZTpl...C_aZKPxgihac0aW9EkL1nOzM"
              },
              {
                "format": "mso_mdoc",
                "credential": "YXNkZnNhZGZkamZqZGFza23....29tZTIzMjMyMzIzMjMy"
              }],
              "c_nonce": "fGFF7UkhLa",
              "c_nonce_expires_in": 86400
        }))
        .unwrap();
    }

    #[test]
    fn example_batch_response_with_deferred() {
        let _: BatchResponse<CoreProfilesCredentialResponse> = serde_json::from_value(json!({
            "credential_responses":[
              {
                 "transaction_id":"8xLOxBtZp8"
              },
              {
                 "format":"jwt_vc_json",
                 "credential":"YXNkZnNhZGZkamZqZGFza23....29tZTIzMjMyMzIzMjMy"
              }
           ],
           "c_nonce":"fGFF7UkhLa",
           "c_nonce_expires_in":86400
        }))
        .unwrap();
    }
}
