use std::collections::HashMap;

use indexmap::IndexMap;
use iref::UriBuf;
use oauth2::{AuthUrl, ClientId, Scope, TokenUrl};
use oid4vci::{
    authorization::{
        authorization_details::CredentialAuthorizationDetailsResponse,
        server::AuthorizationServerMetadata,
    },
    issuer::{
        metadata::{CredentialConfiguration, CredentialDisplay, CredentialIssuerDisplay},
        CredentialIssuerMetadata,
    },
    profile::{dc_sd_jwt::DcSdJwtFormatMetadata, StandardCredentialFormatMetadata},
};
use serde::Deserialize;
use ssi::{
    claims::{
        jwt::{Issuer, StringOrURI, Subject},
        sd_jwt::{JsonPointerBuf, SdAlg, SdJwtBuf},
        JWTClaims,
    },
    JWK,
};

use crate::Params;

pub const DEFAULT_PORT: u32 = 3000;

fn default_port() -> u32 {
    DEFAULT_PORT
}

/// Server configuration.
#[derive(Deserialize)]
pub struct Config {
    /// Listening port.
    #[serde(default = "default_port")]
    pub port: u32,

    /// Enable the Push Authorization Request Endpoint.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pushed-authorization-reques>
    #[serde(default)]
    pub par: bool,

    /// Enable Pre-Authorized Codes.
    #[serde(default)]
    pub pre_auth: bool,

    /// Enabled Credential Offers by reference.
    #[serde(default)]
    pub by_ref: bool,

    /// Transaction Code for Pre-Authorized Codes.
    #[serde(default)]
    pub tx_code: Option<String>,

    /// Authorization Server metadata.
    pub authorization_server_metadata: Option<AuthorizationServerMetadata>,

    /// Credential configurations.
    pub credential_configurations: HashMap<String, CredentialConfigurationConfig>,
}

impl Config {
    /// Adds the command line interface parameters to the configuration.
    pub fn add_params(&mut self, params: &Params) {
        if let Some(port) = params.port {
            self.port = port;
        }

        if params.par {
            self.par = true;
        }

        if params.pre_auth {
            self.pre_auth = true;
        }

        if params.by_ref {
            self.by_ref = true;
        }

        if let Some(tx_code) = params.tx_code.clone() {
            self.tx_code = Some(tx_code)
        }
    }

    /// Authorization Endpoint URL.
    fn authorize_endpoint(&self) -> AuthUrl {
        AuthUrl::new(format!("{}/authorize", self.credential_issuer())).unwrap()
    }

    /// Token Endpoint URL.
    fn token_endpoint(&self) -> TokenUrl {
        TokenUrl::new(format!("{}/token", self.credential_issuer())).unwrap()
    }

    /// Pushed Authorization Request Endpoint URL.
    fn par_endpoint(&self) -> UriBuf {
        UriBuf::new(format!("{}/par", self.credential_issuer()).into_bytes()).unwrap()
    }

    /// Default authorization server metadata.
    pub fn default_authorization_server_metadata(&self) -> AuthorizationServerMetadata {
        let mut metadata =
            AuthorizationServerMetadata::new(self.credential_issuer(), self.token_endpoint())
                .with_authorization_endpoint(self.authorize_endpoint());

        if self.par {
            metadata.pushed_authorization_request_endpoint = Some(self.par_endpoint());
        }

        metadata
    }

    /// Credential issuer identifier URL.
    pub fn credential_issuer(&self) -> UriBuf {
        UriBuf::new(format!("http://127.0.0.1:{}", self.port).into_bytes()).unwrap()
    }

    /// Credential Endpoint URL.
    fn credential_endpoint(&self) -> UriBuf {
        UriBuf::new(format!("{}/credential", self.credential_issuer()).into_bytes()).unwrap()
    }

    /// Deferred Credential Endpoint URL.
    fn deferred_credential_endpoint(&self) -> Option<UriBuf> {
        Some(
            UriBuf::new(format!("{}/deferred_credential", self.credential_issuer()).into_bytes())
                .unwrap(),
        )
    }

    /// Nonce Endpoint URL.
    fn nonce_endpoint(&self) -> Option<UriBuf> {
        Some(UriBuf::new(format!("{}/nonce", self.credential_issuer()).into_bytes()).unwrap())
    }

    /// Notification Endpoint URL.
    fn notification_endpoint(&self) -> Option<UriBuf> {
        Some(
            UriBuf::new(format!("{}/notification", self.credential_issuer()).into_bytes()).unwrap(),
        )
    }

    /// Supported credential configurations.
    ///
    /// To be put in the issuer metadata.
    fn credential_configurations_supported(&self) -> IndexMap<String, CredentialConfiguration> {
        self.credential_configurations
            .iter()
            .map(|(id, config)| (id.clone(), config.metadata()))
            .collect()
    }

    /// Credential issuer metadata.
    pub fn credential_issuer_metadata(&self) -> CredentialIssuerMetadata {
        CredentialIssuerMetadata {
            credential_issuer: self.credential_issuer(),
            credential_endpoint: self.credential_endpoint(),
            deferred_credential_endpoint: self.deferred_credential_endpoint(),
            nonce_endpoint: self.nonce_endpoint(),
            notification_endpoint: self.notification_endpoint(),
            credential_request_encryption: None,
            credential_response_encryption: None,
            batch_credential_issuance: None,
            authorization_servers: vec![],
            display: vec![CredentialIssuerDisplay::new("Test Credential Issuer")],
            credential_configurations_supported: self.credential_configurations_supported(),
        }
    }

    /// Credential authorization details.
    pub fn authorization_details(&self) -> Vec<CredentialAuthorizationDetailsResponse> {
        self.credential_configurations
            .iter()
            .map(|(id, c)| CredentialAuthorizationDetailsResponse {
                credential_configuration_id: id.clone(),
                claims: vec![],
                credential_identifiers: c.credentials.keys().cloned().collect(),
                params: Default::default(),
            })
            .collect()
    }

    /// Gets the credential with the given identifier.
    pub fn get_credential(
        &self,
        id: &str,
    ) -> Option<(&CredentialConfigurationConfig, &serde_json::Value)> {
        for (_, config) in &self.credential_configurations {
            if let Some(value) = config.credentials.get(id) {
                return Some((config, value));
            }
        }

        None
    }
}

#[derive(Deserialize)]
pub struct CredentialConfigurationConfig {
    /// Scope.
    pub scope: Option<Scope>,

    /// Display info.
    #[serde(default)]
    pub display: Vec<CredentialDisplay>,

    /// Credentials.
    pub credentials: HashMap<String, serde_json::Value>,

    /// Credential format.
    #[serde(flatten)]
    pub format: StandardCredentialFormatMetadata,
}

impl CredentialConfigurationConfig {
    fn metadata(&self) -> CredentialConfiguration {
        CredentialConfiguration {
            scope: self.scope.clone(),
            credential_signing_alg_values_supported: vec![],
            cryptographic_binding_methods_supported: vec![],
            proof_types_supported: IndexMap::new(),
            claims: vec![],
            format: self.format.clone(),
            display: self.display.clone(),
        }
    }

    pub async fn sign(
        &self,
        issuer: &str,
        key: &JWK,
        client_id: Option<&ClientId>,
        credential: &serde_json::Value,
        key_binding: Option<&JWK>,
    ) -> serde_json::Value {
        match &self.format {
            StandardCredentialFormatMetadata::DcSdJwt(format) => {
                sign_dc_sd_jwt(issuer, key, client_id, credential, key_binding, format).await
            }
            _ => todo!(),
        }
    }
}

async fn sign_dc_sd_jwt(
    issuer: &str,
    key: &JWK,
    client_id: Option<&ClientId>,
    credential: &serde_json::Value,
    key_binding: Option<&JWK>,
    format: &DcSdJwtFormatMetadata,
) -> serde_json::Value {
    let mut claims: JWTClaims =
        serde_json::from_value(credential.clone()).expect("invalid JWT claims");

    claims
        .registered
        .set(Issuer(StringOrURI::String(issuer.to_owned())));

    if let Some(client_id) = client_id {
        claims.registered.set(Subject(
            client_id
                .as_str()
                .try_into()
                .unwrap_or_else(|_| StringOrURI::String(client_id.as_str().to_owned())),
        ));
    }

    claims.private.set(
        "vct".to_owned(),
        serde_json::Value::String(format.vct.clone()),
    );

    let pointers: &[JsonPointerBuf] = &[];
    let sd_jwt = SdJwtBuf::conceal_and_sign(&claims, SdAlg::Sha256, pointers, key)
        .await
        .unwrap();

    if let Some(_key_binding) = key_binding {
        log::warn!("key binding is not supported by ssi")
    }

    serde_json::Value::String(sd_jwt.into_string())
}
