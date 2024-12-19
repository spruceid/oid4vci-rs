#![allow(clippy::large_enum_variant, deprecated)]

use anyhow::{bail, Context, Result};
use oauth2::{
    http::{self, header::ACCEPT, HeaderValue, Method, StatusCode},
    AsyncHttpClient, SyncHttpClient,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use url::Url;

use crate::{
    http_utils::{check_content_type, MIME_TYPE_JSON},
    types::{
        CredentialConfigurationId, CredentialOfferRequest, IssuerState, IssuerUrl,
        PreAuthorizedCode,
    },
};

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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum CredentialOfferFlat {
    Value { credential_offer: String },
    Reference { credential_offer_uri: Url },
}

impl CredentialOffer {
    pub fn from_request(uri: CredentialOfferRequest) -> Result<Self> {
        match serde_path_to_error::deserialize(serde_urlencoded::Deserializer::new(
            form_urlencoded::parse(uri.url().query().unwrap_or_default().as_bytes()),
        ))? {
            CredentialOfferFlat::Reference {
                credential_offer_uri,
            } => Ok(CredentialOffer::Reference {
                credential_offer_uri,
            }),
            CredentialOfferFlat::Value { credential_offer } => Ok(CredentialOffer::Value {
                credential_offer: serde_json::from_str(
                    &percent_encoding::percent_decode_str(&credential_offer)
                        .decode_utf8()
                        .context("could not percent decode credential offer JSON")?,
                )
                .context("could not decode inner JSON")?,
            }),
        }
    }

    pub fn resolve<C>(self, http_client: &C) -> Result<CredentialOfferParameters>
    where
        C: SyncHttpClient,
        C::Error: Send + Sync,
    {
        let uri = match self {
            CredentialOffer::Value { credential_offer } => return Ok(credential_offer),
            CredentialOffer::Reference {
                credential_offer_uri,
            } => credential_offer_uri,
        };

        let request = Self::build_request(&uri)?;

        let response = http_client
            .call(request)
            .context("error occurred when making the request")?;

        Self::handle_response(response, &uri)
    }

    pub async fn resolve_async<'c, C>(self, http_client: &'c C) -> Result<CredentialOfferParameters>
    where
        C: AsyncHttpClient<'c>,
        C::Error: Send + Sync,
    {
        let uri = match self {
            CredentialOffer::Value { credential_offer } => return Ok(credential_offer),
            CredentialOffer::Reference {
                credential_offer_uri,
            } => credential_offer_uri,
        };

        let request = Self::build_request(&uri)?;

        let response = http_client
            .call(request)
            .await
            .context("error occurred when making the request")?;

        Self::handle_response(response, &uri)
    }

    fn build_request(url: &Url) -> Result<http::Request<Vec<u8>>> {
        http::Request::builder()
            .uri(url.as_str())
            .method(Method::GET)
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .body(Vec::new())
            .context("failed to prepare request")
    }

    fn handle_response(
        response: http::Response<Vec<u8>>,
        url: &Url,
    ) -> Result<CredentialOfferParameters> {
        if response.status() != StatusCode::OK {
            bail!("HTTP status code {} at {}", response.status(), url)
        }

        check_content_type(response.headers(), MIME_TYPE_JSON)?;

        serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(response.body()))
            .context("failed to parse response body")
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialOfferParameters {
    credential_issuer: IssuerUrl,
    credential_configuration_ids: Vec<CredentialConfigurationId>,
    grants: Option<CredentialOfferGrants>,
}

impl CredentialOfferParameters {
    pub fn new(
        credential_issuer: IssuerUrl,
        credential_configuration_ids: Vec<CredentialConfigurationId>,
        grants: Option<CredentialOfferGrants>,
    ) -> Self {
        Self {
            credential_issuer,
            credential_configuration_ids,
            grants,
        }
    }

    pub fn issuer(&self) -> &IssuerUrl {
        &self.credential_issuer
    }

    pub fn grants(&self) -> Option<&CredentialOfferGrants> {
        self.grants.as_ref()
    }

    pub fn credential_configuration_ids(&self) -> &[CredentialConfigurationId] {
        &self.credential_configuration_ids
    }

    pub fn authorization_code_grant(&self) -> Option<&AuthorizationCodeGrant> {
        self.grants()?.authorization_code()
    }

    pub fn pre_authorized_code_grant(&self) -> Option<&PreAuthorizedCodeGrant> {
        self.grants()?.pre_authorized_code()
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialOfferGrants {
    authorization_code: Option<AuthorizationCodeGrant>,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

impl CredentialOfferGrants {
    pub fn new(
        authorization_code: Option<AuthorizationCodeGrant>,
        pre_authorized_code: Option<PreAuthorizedCodeGrant>,
    ) -> Self {
        Self {
            authorization_code,
            pre_authorized_code,
        }
    }
    field_getters_setters![
        pub self [self] ["credential offer grants"] {
            set_authorization_code -> authorization_code[Option<AuthorizationCodeGrant>],
            set_pre_authorized_code -> pre_authorized_code[Option<PreAuthorizedCodeGrant>],
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
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pre_authorized_code: PreAuthorizedCode,
    tx_code: Option<TxCodeDefinition>,
    interval: Option<usize>,
    authorization_server: Option<IssuerUrl>,
}

impl PreAuthorizedCodeGrant {
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
