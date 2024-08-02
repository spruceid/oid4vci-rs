#![allow(clippy::large_enum_variant)]

use openidconnect::{CsrfToken, IssuerUrl, Scope};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use url::Url;

use crate::profiles::CredentialOfferProfile;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CredentialOffer {
    Value {
        credential_offer: CredentialOfferParameters,
    },
    Reference {
        credential_offer_uri: Url,
    },
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialOfferParameters {
    credential_issuer: IssuerUrl,
    credential_configuration_ids: Vec<String>,
    grants: Option<CredentialOfferGrants>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CredentialOfferFormat<CO>
where
    CO: CredentialOfferProfile,
{
    Reference(Scope),
    #[serde(bound = "CO: CredentialOfferProfile")]
    Value(CO),
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialOfferGrants {
    authorization_code: Option<AuthorizationCodeGrant>,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pre_authorized_code: Option<PreAuthorizationCodeGrant>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationCodeGrant {
    issuer_state: Option<CsrfToken>,
    authorization_server: Option<IssuerUrl>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreAuthorizationCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pre_authorized_code: String,
    tx_code: Option<TxCode>,
    interval: Option<usize>,
    authorization_server: Option<IssuerUrl>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum InputMode {
    #[serde(rename = "numeric")]
    Numeric,
    #[serde(rename = "text")]
    Text,
}

impl Default for InputMode {
    fn default() -> Self {
        Self::Numeric
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxCode {
    input_mode: Option<InputMode>,
    length: Option<usize>,
    description: Option<String>,
}

impl TxCode {
    pub fn new(
        input_mode: Option<InputMode>,
        length: Option<usize>,
        description: Option<String>,
    ) -> Self {
        Self {
            input_mode,
            length,
            description,
        }
    }

    field_getters_setters![
        pub self [self] ["transaction code value"] {
            set_input_mode -> input_mode[Option<InputMode>],
            set_length -> length[Option<usize>],
            set_description -> description[Option<String>],
        }
    ];
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn example_credential_offer_object() {
        let _: CredentialOfferParameters = serde_json::from_value(json!({
           "credential_issuer": "https://credential-issuer.example.com",
           "credential_configuration_ids": [
              "UniversityDegreeCredential",
              "org.iso.18013.5.1.mDL"
           ],
           "grants": {
              "authorization_code": {
                 "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
              },
              "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                 "pre-authorized_code": "adhjhdjajkdkhjhdj",
                 "tx_code": {
                   "length": 4,
                   "input_mode": "numeric",
                   "description": "Please provide the one-time code that was sent via e-mail"
                 }
              }
           }
        }))
        .unwrap();
    }
}
