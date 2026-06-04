use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use indexmap::IndexMap;
use iref::UriBuf;
use oid4vci::{
    authorization::{
        authorization_details::CredentialAuthorizationDetailsResponse,
        server::Oid4vciAuthorizationServerMetadata,
    },
    issuer::{
        metadata::{
            CredentialConfiguration, CredentialDisplay, CredentialIssuerDisplay,
            CryptographicBindingMethod, KeyProofTypesSupported,
        },
        CredentialIssuerMetadata,
    },
    profile::{dc_sd_jwt::DcSdJwtFormatMetadata, StandardCredentialFormatMetadata},
};
use open_auth2::{
    ext::pkce::PkceCodeChallengeMethod,
    server::metadata::{GrantType, TokenEndpointAuthMethod},
    ClientId, ScopeBuf,
};
use serde::Deserialize;
use serde_json::json;
use ssi::jwk::Algorithm;
use ssi::{claims::jws::JwsSigner, JWK};

/// Default credential configuration id (matches the conformance suite default).
pub const DEFAULT_CREDENTIAL_CONFIGURATION_ID: &str = "eu.europa.ec.eudi.pid.1";

/// Server configuration.
#[derive(Deserialize)]
pub struct Config {
    /// Listening port.
    pub port: u32,

    /// Public URL the issuer is reachable at (e.g. the ngrok URL). Used as the
    /// Credential Issuer identifier and to build all advertised endpoints.
    #[serde(skip)]
    pub public_url: Option<UriBuf>,

    /// Enable the Pushed Authorization Request Endpoint.
    #[serde(default)]
    pub par: bool,

    /// Enable Pre-Authorized Codes.
    #[serde(default)]
    pub pre_auth: bool,

    /// Enable Credential Offers by reference.
    #[serde(default)]
    pub by_ref: bool,

    /// Transaction Code for Pre-Authorized Codes.
    #[serde(default)]
    pub tx_code: Option<String>,

    /// Authorization Server metadata override.
    pub authorization_server_metadata: Option<Oid4vciAuthorizationServerMetadata>,

    /// Registered client redirect URIs. When non-empty, an authorization
    /// request's `redirect_uri` must be one of these or it is rejected
    /// (FAPI2 §5.3.1.1 / RFC 6749 §3.1.2.3). Empty accepts any.
    #[serde(default)]
    pub registered_redirect_uris: Vec<UriBuf>,

    /// Require an interactive consent step at the Authorization Endpoint instead
    /// of auto-approving. When set, a valid pushed request renders an
    /// approve/deny page rather than redirecting immediately; the `request_uri`
    /// is consumed only once the user decides. Needed for the FAPI2 tests that
    /// require the user to deny consent (`access_denied`, RFC 6749 §4.1.2.1) or
    /// to reuse a `request_uri` before authentication completes.
    #[serde(default)]
    pub manual_consent: bool,

    /// Credential configurations.
    pub credential_configurations: HashMap<String, CredentialConfigurationConfig>,
}

impl Config {
    /// Builds a conformance configuration reachable at `public_url`, with PAR
    /// enabled and a default `eu.europa.ec.eudi.pid.1` SD-JWT VC credential.
    pub fn new(public_url: UriBuf, port: u32, registered_redirect_uris: Vec<UriBuf>) -> Self {
        let mut credential_configurations = HashMap::new();
        credential_configurations.insert(
            DEFAULT_CREDENTIAL_CONFIGURATION_ID.to_owned(),
            CredentialConfigurationConfig {
                scope: ScopeBuf::new(DEFAULT_CREDENTIAL_CONFIGURATION_ID.to_owned()).ok(),
                display: vec![],
                credentials: HashMap::from([(
                    "pid".to_owned(),
                    json!({
                        "given_name": "Erika",
                        "family_name": "Mustermann",
                        "birthdate": "1963-08-12"
                    }),
                )]),
                format: StandardCredentialFormatMetadata::DcSdJwt(DcSdJwtFormatMetadata {
                    vct: DEFAULT_CREDENTIAL_CONFIGURATION_ID.to_owned(),
                }),
            },
        );

        Self {
            port,
            public_url: Some(public_url),
            par: true,
            pre_auth: false,
            by_ref: false,
            tx_code: None,
            authorization_server_metadata: None,
            registered_redirect_uris,
            manual_consent: false,
            credential_configurations,
        }
    }

    /// Authorization Endpoint URL.
    fn authorize_endpoint(&self) -> UriBuf {
        UriBuf::new(format!("{}/authorize", self.credential_issuer()).into_bytes()).unwrap()
    }

    /// Token Endpoint URL.
    fn token_endpoint(&self) -> UriBuf {
        UriBuf::new(format!("{}/token", self.credential_issuer()).into_bytes()).unwrap()
    }

    /// Pushed Authorization Request Endpoint URL.
    fn par_endpoint(&self) -> UriBuf {
        UriBuf::new(format!("{}/par", self.credential_issuer()).into_bytes()).unwrap()
    }

    /// Default authorization server metadata.
    pub fn default_authorization_server_metadata(&self) -> Oid4vciAuthorizationServerMetadata {
        let mut metadata: Oid4vciAuthorizationServerMetadata =
            Oid4vciAuthorizationServerMetadata::new(self.credential_issuer())
                .with_authorization_endpoint(self.authorize_endpoint())
                .with_token_endpoint(self.token_endpoint());

        // FAPI2 / HAIP required Authorization Server metadata.
        metadata.response_types_supported = Some(vec!["code".to_owned()]);
        // FAPI2 forbids the implicit grant; advertise only authorization_code.
        metadata.grant_types_supported = vec![GrantType::AuthorizationCode];
        metadata.code_challenge_methods_supported = Some(vec![PkceCodeChallengeMethod::S256]);
        // RFC 9207 / FAPI2 §5.3.2.2: we set the `iss` parameter in the
        // authorization response, so advertise support for it.
        metadata.authorization_response_iss_parameter_supported = Some(true);
        // Attestation-Based Client Authentication (HAIP §4.3): advertise the
        // `attest_jwt_client_auth` token endpoint auth method and the JWS algs
        // supported for the Client Attestation JWT (ATCA-07 §13.3).
        metadata.token_endpoint_auth_methods_supported = vec![TokenEndpointAuthMethod::Extension(
            "attest_jwt_client_auth".to_owned(),
        )];
        metadata
            .extra
            .client_attestation
            .client_attestation_signing_alg_values_supported = vec![Algorithm::ES256];
        metadata
            .extra
            .client_attestation
            .client_attestation_pop_signing_alg_values_supported = vec![Algorithm::ES256];
        metadata.scopes_supported = Some(
            self.credential_configurations
                .values()
                .filter_map(|c| c.scope.clone())
                .collect(),
        );
        metadata.extra.dpop.dpop_signing_alg_values_supported = vec![Algorithm::ES256];

        if self.par {
            metadata.extra.pushed_authorization_request_endpoint = Some(self.par_endpoint());
            metadata.extra.require_pushed_authorization_requests = true;
        }

        metadata
    }

    /// Credential issuer identifier URL.
    pub fn credential_issuer(&self) -> UriBuf {
        match &self.public_url {
            Some(url) => url.clone(),
            None => UriBuf::new(format!("http://127.0.0.1:{}", self.port).into_bytes()).unwrap(),
        }
    }

    /// Credential Endpoint URL.
    pub fn credential_endpoint(&self) -> UriBuf {
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
            // The issuer is also the Authorization Server; list it explicitly so
            // the wallet can select it (OID4VCI §12.2.3).
            authorization_servers: vec![self.credential_issuer()],
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
    pub scope: Option<ScopeBuf>,

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
        // Advertise `jwt` key proofs and `jwk` binding, as required by the HAIP
        // profile so the wallet knows it must send a (key-attested) JWT proof.
        let mut proof_types_supported = IndexMap::new();
        proof_types_supported.insert(
            "jwt".to_owned(),
            serde_json::from_value::<KeyProofTypesSupported>(json!({
                "proof_signing_alg_values_supported": ["ES256"]
            }))
            .unwrap(),
        );

        CredentialConfiguration {
            scope: self.scope.clone(),
            credential_signing_alg_values_supported: vec![json!("ES256")],
            cryptographic_binding_methods_supported: vec![CryptographicBindingMethod::Jwk],
            proof_types_supported,
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
    let mut claims = credential.clone();
    let obj = claims
        .as_object_mut()
        .expect("credential claims must be a JSON object");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    obj.insert("iss".to_owned(), json!(issuer));
    obj.insert("vct".to_owned(), json!(format.vct));
    obj.insert("iat".to_owned(), json!(now));
    // HAIP §6.1: limit the credential's validity.
    obj.insert("exp".to_owned(), json!(now + 3600));

    if let Some(client_id) = client_id {
        obj.insert("sub".to_owned(), json!(client_id.as_str()));
    }

    // SD-JWT VC holder binding (RFC 7800 `cnf`): bind the credential to the key
    // the wallet proved possession of, as a public JWK.
    if let Some(key_binding) = key_binding {
        obj.insert("cnf".to_owned(), json!({ "jwk": key_binding.to_public() }));
    }

    // Build the issuer-signed JWT with the SD-JWT VC media type (`typ`) and the
    // issuer's certificate chain in the `x5c` JOSE header, so the wallet can
    // validate the signature against the credential trust anchor (HAIP §6.1.1,
    // SD-JWT VC §3.2.1).
    let mut header = json!({ "alg": "ES256", "typ": "dc+sd-jwt" });
    if let Some(x5c) = &key.x509_certificate_chain {
        header["x5c"] = json!(x5c);
    }

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signing_input = format!(
        "{}.{}",
        b64.encode(serde_json::to_vec(&header).unwrap()),
        b64.encode(serde_json::to_vec(&claims).unwrap()),
    );
    let signature = key.sign_bytes(signing_input.as_bytes()).await.unwrap();
    let jws = format!("{signing_input}.{}", b64.encode(signature));

    // SD-JWT with no concealed claims: `<issuer-signed JWT>~`.
    serde_json::Value::String(format!("{jws}~"))
}
