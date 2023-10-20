pub mod jwt;
pub mod jwtld;
pub mod ldp;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::metadata::IssuerMetadataDisplay;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDefinition {
    r#type: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_subject: Option<HashMap<String, CredentialSubjectClaims>>,
}

impl CredentialDefinition {
    pub fn new(r#type: Vec<String>) -> Self {
        Self {
            r#type,
            credential_subject: None,
        }
    }

    field_getters_setters![
        pub self [self] ["credential definition value"] {
            set_type -> r#type[Vec<String>],
            set_credential_subject -> credential_subject[Option<HashMap<String, CredentialSubjectClaims>>],
        }
    ];
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialOfferDefinition {
    r#type: Vec<String>,
}

impl CredentialOfferDefinition {
    pub fn new(r#type: Vec<String>) -> Self {
        Self { r#type }
    }

    field_getters_setters![
        pub self [self] ["credential offer definition value"] {
            set_type -> r#type[Vec<String>],
        }
    ];
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CredentialSubjectClaims {
    mandatory: Option<bool>,
    value_type: Option<String>,
    display: Option<Vec<IssuerMetadataDisplay>>,
}

impl CredentialSubjectClaims {
    pub fn new() -> Self {
        Self {
            mandatory: None,
            value_type: None,
            display: None,
        }
    }

    field_getters_setters![
        pub self [self] ["credential subject claims value"] {
            set_mandatory -> mandatory[Option<bool>],
            set_value_type -> value_type[Option<String>],
            set_display -> display[Option<Vec<IssuerMetadataDisplay>>],
        }
    ];
}

// #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
// pub struct JWTLDVC {}
