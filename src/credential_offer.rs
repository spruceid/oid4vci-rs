#![allow(clippy::large_enum_variant)]

use oauth2::Scope;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use url::Url;

use crate::{
    profiles::CredentialOfferProfile,
    types::{IssuerState, IssuerUrl, PreAuthorizedCode},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CredentialOffer<CO>
where
    CO: CredentialOfferProfile,
{
    Value {
        #[serde(bound = "CO: CredentialOfferProfile")]
        credential_offer: CredentialOfferParameters<CO>,
    },
    Reference {
        credential_offer_uri: Url,
    },
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CredentialOfferParameters<CO>
where
    CO: CredentialOfferProfile,
{
    Value {
        credential_issuer: IssuerUrl,
        #[serde(bound = "CO: CredentialOfferProfile")]
        credentials: Vec<CredentialOfferFormat<CO>>,
        grants: Option<CredentialOfferGrants>,
    },
    Reference {
        credential_issuer: IssuerUrl,
        credential_configuration_ids: Vec<String>,
        grants: Option<CredentialOfferGrants>,
    },
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
impl CredentialOfferGrants {
    pub fn new(
        authorization_code: Option<AuthorizationCodeGrant>,
        pre_authorized_code: Option<PreAuthorizationCodeGrant>,
    ) -> Self {
        Self {
            authorization_code,
            pre_authorized_code,
        }
    }
    field_getters_setters![
        pub self [self] ["credential offer grants"] {
            set_authorization_code -> authorization_code[Option<AuthorizationCodeGrant>],
            set_pre_authorized_code -> pre_authorized_code[Option<PreAuthorizationCodeGrant>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationCodeGrant {
    issuer_state: Option<IssuerState>,
    authorization_server: Option<IssuerUrl>,
}
impl AuthorizationCodeGrant {
    pub fn new(issuer_state: Option<IssuerState>, authorization_server: Option<IssuerUrl>) -> Self {
        Self {
            issuer_state,
            authorization_server,
        }
    }
    field_getters_setters![
        pub self [self] ["authorization code grants"] {
            set_issuer_state -> issuer_state[Option<IssuerState>],
            set_authorization_server -> authorization_server[Option<IssuerUrl>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreAuthorizationCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pre_authorized_code: PreAuthorizedCode,
    tx_code: Option<TxCodeDefinition>,
    interval: Option<usize>,
    authorization_server: Option<IssuerUrl>,
}

impl PreAuthorizationCodeGrant {
    pub fn new(pre_authorized_code: PreAuthorizedCode) -> Self {
        Self {
            pre_authorized_code,
            tx_code: None,
            interval: None,
            authorization_server: None,
        }
    }
    field_getters_setters![
        pub self [self] ["pre-authorized_code grants"] {
            set_pre_authorized_code -> pre_authorized_code[PreAuthorizedCode],
            set_tx_code -> tx_code[Option<TxCodeDefinition>],
            set_interval -> interval[Option<usize>],
            set_authorization_server -> authorization_server[Option<IssuerUrl>],
        }
    ];
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
pub struct TxCodeDefinition {
    input_mode: Option<InputMode>,
    length: Option<usize>,
    description: Option<String>,
}

impl TxCodeDefinition {
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

    use crate::core::profiles::CoreProfilesOffer;

    use super::*;

    #[test]
    fn example_credential_offer_object_reference() {
        let _: CredentialOfferParameters<CoreProfilesOffer> = serde_json::from_value(json!({
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

    #[test]
    fn example_credential_offer_object_value() {
        let _: CredentialOfferParameters<CoreProfilesOffer> = serde_json::from_value(json!({
            "credential_issuer": "https://credential-issuer.example.com",
            "credentials": [{
                "format": "jwt_vc_json-ld",
                "credential_definition": {
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://www.w3.org/2018/credentials/examples/v1"
                    ],
                    "type": [
                        "VerifiableCredential",
                        "UniversityDegreeCredential"
                    ]
                }
            }, {
                "format": "mso_mdoc",
                "doctype": "org.iso.18013.5.1.mDL",
            }],
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
