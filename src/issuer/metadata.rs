use std::fmt::Debug;

use anyhow::bail;
use indexmap::IndexMap;
use iref::{uri_ref, Uri, UriBuf, UriRef};
use langtag::LangTagBuf;
use oauth2::Scope;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use ssi_jwk::JWK;

use crate::{
    encryption::jwe, profile::StandardCredentialFormatMetadata, util::discoverable::Discoverable,
};

/// Credential Issuer Metadata.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "F: CredentialFormatMetadata")]
pub struct CredentialIssuerMetadata<F = StandardCredentialFormatMetadata>
where
    F: CredentialFormatMetadata,
{
    /// Credential Issuer's identifier.
    ///
    /// A Credential Issuer is identified by a case sensitive URL using the
    /// https scheme that contains scheme, host and, optionally, port number and
    /// path components, but no query or fragment components.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#credential-issuer-identifier>
    pub credential_issuer: UriBuf,

    /// List of OAuth 2.0 Authorization Server (as defined in [RFC8414]) the
    /// Credential Issuer relies on for authorization.
    ///
    /// If this parameter is omitted, the entity providing the Credential Issuer
    /// is also acting as the Authorization Server, i.e., the Credential
    /// Issuer's identifier is used to obtain the Authorization Server metadata.
    ///
    /// [RFC8414]: <https://www.rfc-editor.org/info/rfc8414>
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub authorization_servers: Vec<UriBuf>,

    /// URL of the Credential Issuer's Credential Endpoint.
    ///
    /// This URL *must* use the `https` scheme and *may* contain port, path, and
    /// query parameter components.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#credential-request>
    pub credential_endpoint: UriBuf,

    /// URL of the Credential Issuer's Nonce Endpoint.
    ///
    /// This URL *must* use the `https` scheme and *may* contain port, path, and
    /// query parameter components. If omitted, the Credential Issuer does not
    /// require the use of `c_nonce`.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#nonce-endpoint>
    pub nonce_endpoint: Option<UriBuf>,

    /// URL of the Credential Issuer's Deferred Credential Endpoint.
    ///
    /// This URL *must* use the `https` scheme and *may* contain port, path, and
    /// query parameter components.
    ///
    /// If omitted, the Credential Issuer does not support the Deferred
    /// Credential Endpoint.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#deferred-credential-issuance>
    pub deferred_credential_endpoint: Option<UriBuf>,

    /// URL of the Credential Issuer's Notification Endpoint.
    ///
    /// This URL *must* use the `https` scheme and *may* contain port, path, and
    /// query parameter components.
    ///
    /// If omitted, the Credential Issuer does not support the Notification
    /// Endpoint.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#notification-endpoint>
    pub notification_endpoint: Option<UriBuf>,

    /// Information about whether the Credential Issuer supports encryption of
    /// the Credential Request on top of TLS.
    pub credential_request_encryption: Option<CredentialRequestEncryptionMetadata>,

    /// Information about whether the Credential Issuer supports encryption of
    /// the Credential Response on top of TLS.
    pub credential_response_encryption: Option<CredentialResponseEncryptionMetadata>,

    /// Information about the Credential Issuer's support for issuance of
    /// multiple Credentials in a batch in the Credential Endpoint.
    ///
    /// If omitted, the Credential Issuer does not support batch issuance.
    pub batch_credential_issuance: Option<BatchCredentialIssuanceMetadata>,

    /// Credential Issuer display properties.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub display: Vec<CredentialIssuerDisplay>,

    /// Specifics of the Credential that the Credential Issuer supports issuance
    /// of.
    ///
    /// List of name/value pairs, where each name is a unique identifier of the
    /// supported Credential being described.
    pub credential_configurations_supported: IndexMap<String, CredentialConfiguration<F>>,
}

impl<P: CredentialFormatMetadata> Discoverable for CredentialIssuerMetadata<P> {
    const WELL_KNOWN_URI_REF: &UriRef = uri_ref!(".well-known/openid-credential-issuer");

    fn validate(&self, issuer: &Uri) -> anyhow::Result<()> {
        if self.credential_issuer != issuer {
            bail!(
                "unexpected issuer URI `{}` (expected `{}`)",
                self.credential_issuer,
                issuer
            )
        }
        Ok(())
    }
}

impl<P: CredentialFormatMetadata> CredentialIssuerMetadata<P> {
    pub fn new(credential_issuer: UriBuf, credential_endpoint: UriBuf) -> Self {
        Self {
            credential_issuer,
            authorization_servers: Vec::new(),
            credential_endpoint,
            nonce_endpoint: None,
            deferred_credential_endpoint: None,
            notification_endpoint: None,
            credential_request_encryption: None,
            credential_response_encryption: None,
            batch_credential_issuance: None,
            display: Vec::new(),
            credential_configurations_supported: IndexMap::new(),
        }
    }
}

/// Information about whether the Credential Issuer supports encryption of the
/// Credential Request on top of TLS.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialRequestEncryptionMetadata {
    /// Set of JWK public keys to be used by the Wallet as input to a key
    /// agreement for encryption of the Credential Request.
    ///
    /// Must contain at least one key. Each JWK in the set *must* have a `kid`
    /// (key ID) parameter that uniquely identifies the key.
    ///
    /// See: <https://www.rfc-editor.org/info/rfc7591>
    pub jwks: Vec<JWK>,

    /// List of the JWE encryption algorithms (`enc` values) supported by the
    /// Credential Endpoint to decode the Credential Request from a JWT.
    ///
    /// Must contain at least one algorithm.
    pub enc_values_supported: Vec<jwe::EncryptionAlgorithm>,

    /// List of the JWE compression algorithms (`zip` values) supported by the
    /// Credential Endpoint to uncompress the Credential Request after
    /// decryption.
    ///
    /// If empty, no compression algorithms are supported.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub zip_values_supported: Vec<jwe::CompressionAlgorithm>,

    /// Whether the Credential Issuer requires the additional encryption on top
    /// of TLS for the Credential Requests.
    ///
    /// If `true`, the Credential Issuer requires encryption for every
    /// Credential Request. Otherwise the Wallet *may* choose whether it
    /// encrypts the request or not.
    pub encryption_required: bool,
}

/// Information about whether the Credential Issuer supports encryption of the
/// Credential Response on top of TLS.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialResponseEncryptionMetadata {
    /// List of the JWE encryption algorithms (`alg` values) supported by the
    /// Credential Endpoint to encode the Credential Response in a JWT.
    ///
    /// Must contain at least one value.
    pub alg_values_supported: Vec<jwe::Algorithm>,

    /// List of the JWE encryption algorithm (`enc` values) supported by the
    /// Credential Endpoint to encode the Credential Response in a JWT.
    ///
    /// Must contain at least one value.
    pub enc_values_supported: Vec<jwe::EncryptionAlgorithm>,

    /// List of the JWE compression algorithms (`zip` values) supported by the
    /// Credential Endpoint to uncompress the Credential Response prior to
    /// encryption.
    ///
    /// If empty, no compression algorithms are supported.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub zip_values_supported: Vec<jwe::CompressionAlgorithm>,

    /// Whether the Credential Issuer requires the additional encryption on top
    /// of TLS for the Credential Response.
    ///
    /// If `true`, the Credential Issuer requires encryption for every
    /// Credential Response and therefore the Wallet *must* provide encryption
    /// keys in the Credential Request. Otherwise the Wallet *may* choose
    /// whether it provides encryption keys or not.
    pub encryption_required: bool,
}

/// Information about the Credential Issuer's support for issuance of multiple
/// Credentials in a batch in the Credential Endpoint.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BatchCredentialIssuanceMetadata {
    /// Integer value specifying the maximum array size for the `proofs`
    /// parameter in a Credential Request.
    ///
    /// It *must* be `2` or greater.
    pub batch_size: u32,
}

/// Credential Issuer display properties.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialIssuerDisplay {
    /// Display name for the Credential Issuer.
    pub name: Option<String>,

    /// Language of this object.
    pub locale: Option<LangTagBuf>,

    /// Information about the logo of the Credential Issuer.
    pub logo: Option<DisplayLogoMetadata>,
}

impl CredentialIssuerDisplay {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            locale: None,
            logo: None,
        }
    }
}

/// Logo of a Credential Issuer.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DisplayLogoMetadata {
    /// URI where the Wallet can obtain the logo of the Credential Issuer.
    pub uri: UriBuf,

    /// Alternative text for the logo image.
    pub alt_text: Option<String>,
}

impl DisplayLogoMetadata {
    pub fn new(uri: UriBuf, alt_text: Option<String>) -> Self {
        Self { uri, alt_text }
    }
}

/// Credential format metadata.
///
/// Provides format-specific metadata included in a
/// [`CredentialIssuerMetadata`].
///
/// Implementors *must* serialize as a struct with a `format` string field
/// identifying the format. It may also include additional format-specific
/// fields, all serializable as JSON.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p>
pub trait CredentialFormatMetadata: Clone + Serialize + DeserializeOwned {
    /// Credential format identifier.
    type Format;

    /// Supported signing algorithms.
    type SigningAlgorithm: Debug + Clone + PartialEq + Eq + Serialize + DeserializeOwned;

    /// Returns the format identifier.
    ///
    /// This corresponds to the `format` field.
    fn id(&self) -> Self::Format;
}

/// Any credential format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyCredentialFormatConfiguration {
    /// Format identifier.
    #[serde(rename = "format")]
    pub id: String,

    /// Any format-specific property.
    pub properties: IndexMap<String, serde_json::Value>,
}

impl CredentialFormatMetadata for AnyCredentialFormatConfiguration {
    type Format = String;

    type SigningAlgorithm = serde_json::Value;

    fn id(&self) -> String {
        self.id.clone()
    }
}

/// Credential Issuer Metadata `credential_configurations_supported` parameter
/// value.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p>
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "F: CredentialFormatMetadata")]
pub struct CredentialConfiguration<F: CredentialFormatMetadata = StandardCredentialFormatMetadata> {
    /// String identifying the scope value that this Credential Issuer supports
    /// for this particular Credential.
    ///
    /// The value can be the same across multiple
    /// [`CredentialConfiguration`]s.
    pub scope: Option<Scope>,

    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub credential_signing_alg_values_supported: Vec<F::SigningAlgorithm>,

    /// Case sensitive strings that identify the representation of the
    /// cryptographic key material that the issued Credential is bound to.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub cryptographic_binding_methods_supported: Vec<CryptographicBindingMethod>,

    /// Specifics of the key proof(s) that the Credential Issuer supports.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub proof_types_supported: IndexMap<String, KeyProofTypesSupported>,

    /// Display properties of the supported Credential for different languages.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub display: Vec<CredentialDisplay>,

    /// Claims descriptions.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub claims: Vec<ClaimDescription>,

    /// Credential format and metadata.
    #[serde(flatten)]
    pub format: F,
}

impl<F: CredentialFormatMetadata> CredentialConfiguration<F> {
    pub fn new(format: F) -> Self {
        Self {
            scope: None,
            cryptographic_binding_methods_supported: Vec::new(),
            credential_signing_alg_values_supported: Vec::new(),
            proof_types_supported: IndexMap::new(),
            display: Vec::new(),
            claims: Vec::new(),
            format,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct KeyProofTypesSupported {
    /// Algorithms that the Issuer supports for this proof type.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#proof-types>
    pub proof_signing_alg_values_supported: Vec<ssi_jwk::Algorithm>,

    /// Requirements for key attestations.
    ///
    /// If omitted, the Credential Issuer does not require a key attestation.
    /// Parameters may be empty, indicating a key attestation is needed without
    /// additional constraints.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#keyattestation>
    pub key_attestations_required: Option<KeyAttestationRequirements>,
}

/// Requirements for key attestations.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#keyattestation-apr>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct KeyAttestationRequirements {
    /// Accepted values for a key attestation `key_storage` parameter.
    pub key_storage: Option<Vec<String>>,

    /// Accepted values for a key attestation `user_authentication` parameter.
    pub user_authentication: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CryptographicBindingMethod {
    #[serde(rename = "jwk")]
    Jwk,

    #[serde(rename = "cose_key")]
    Cose,

    #[serde(rename = "mso")]
    MSO,

    #[serde(rename = "did:")]
    Did,

    #[cfg(test)]
    #[serde(rename = "did:example")]
    DidExample,

    #[serde(untagged)]
    Other(String),
}

/// Display properties of a Credential for a certain language.
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CredentialDisplay {
    /// Display name for the Credential.
    pub name: String,

    /// Language of this object.
    pub locale: Option<LangTagBuf>,

    /// Information about the logo of the Credential.
    pub logo: Option<DisplayLogoMetadata>,

    /// Description of the Credential.
    pub description: Option<String>,

    /// Background color of the Credential.
    ///
    /// Represented as a numerical color value defined in
    /// [CSS Color Module Level 3](https://www.w3.org/TR/2022/REC-css-color-3-20220118/).
    pub background_color: Option<String>,

    /// Information about the background image of the Credential.
    pub background_image: Option<BackgroundImageMetadata>,

    /// Text color of the Credential.
    ///
    /// Represented as a numerical color value defined in
    /// [CSS Color Module Level 3](https://www.w3.org/TR/2022/REC-css-color-3-20220118/).
    pub text_color: Option<String>,
}

impl CredentialDisplay {
    pub fn new(
        name: String,
        locale: Option<LangTagBuf>,
        logo: Option<DisplayLogoMetadata>,
        description: Option<String>,
        background_color: Option<String>,
        background_image: Option<BackgroundImageMetadata>,
        text_color: Option<String>,
    ) -> Self {
        Self {
            name,
            locale,
            logo,
            description,
            background_color,
            background_image,
            text_color,
        }
    }
}

/// Information about the background image of a Credential.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BackgroundImageMetadata {
    /// URI where the Wallet can obtain the background image of the Credential.
    pub uri: UriBuf,
}

impl BackgroundImageMetadata {
    pub fn new(uri: UriBuf) -> Self {
        Self { uri }
    }
}

/// Credential claim description.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#claims-description-issuer-metadata>
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ClaimDescription {
    /// Claims path pointer.
    ///
    /// Specifies the path to a claim within the credential.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#claims_path_pointer>
    pub path: Vec<ClaimPathSegment>,

    /// Whether the Credential Issuer will always include this claim in the
    /// issued Credential.
    #[serde(default, skip_serializing_if = "crate::util::is_false")]
    pub mandatory: bool,

    /// Display properties of the claim.
    #[serde(default, skip_serializing_if = "<[_]>::is_empty")]
    pub display: Vec<ClaimDisplay>,
}

/// Claim path segment.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#claims_path_pointer>
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ClaimPathSegment {
    Null,
    Integer(u64),
    String(String),
}

/// Display properties of a credential claim.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ClaimDisplay {
    /// Display name for the claim.
    pub name: Option<String>,

    /// Language of this object.
    pub locale: Option<LangTagBuf>,
}

/// To test examples that focus on the `credential_configurations_supported`
/// property.
#[cfg(test)]
#[derive(Serialize, Deserialize)]
#[serde(bound = "F: CredentialFormatMetadata")]
pub struct CredentialConfigurationsSupported<
    F: CredentialFormatMetadata = StandardCredentialFormatMetadata,
> {
    #[allow(unused)]
    pub credential_configurations_supported: IndexMap<String, CredentialConfiguration<F>>,
}

#[cfg(feature = "axum")]
mod axum {
    use ::axum::{
        body::Body,
        http::{header::CONTENT_TYPE, StatusCode},
        response::{IntoResponse, Response},
    };

    use crate::util::http::MIME_TYPE_JSON;

    use super::*;

    impl<P> IntoResponse for CredentialIssuerMetadata<P>
    where
        P: CredentialFormatMetadata,
    {
        fn into_response(self) -> Response {
            (&self).into_response()
        }
    }

    impl<P> IntoResponse for &CredentialIssuerMetadata<P>
    where
        P: CredentialFormatMetadata,
    {
        fn into_response(self) -> ::axum::response::Response {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, MIME_TYPE_JSON)
                .body(Body::from(
                    serde_json::to_vec(self)
                        // UNWRAP SAFETY: Issuer Metadata is always serializable as JSON.
                        .unwrap(),
                ))
                .unwrap()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn example() {
        let _: CredentialConfigurationsSupported =
            serde_json::from_str(include_str!("../tests/issuer/metadata/example.json")).unwrap();
    }

    #[test]
    fn example_additional() {
        let _: CredentialIssuerMetadata = serde_json::from_str(include_str!(
            "../tests/issuer/metadata/example_additional.json"
        ))
        .unwrap();
    }

    #[test]
    fn example_dc_sd_jwt() {
        let _: CredentialConfigurationsSupported = serde_json::from_str(include_str!(
            "../tests/profile/dc_sd_jwt/issuer_metadata.json"
        ))
        .unwrap();
    }

    #[test]
    fn example_mso_mdoc() {
        let _: CredentialConfigurationsSupported = serde_json::from_str(include_str!(
            "../tests/profile/mso_mdoc/issuer_metadata.json"
        ))
        .unwrap();
    }

    #[test]
    fn example_w3c_vc() {
        let _: CredentialConfigurationsSupported =
            serde_json::from_str(include_str!("../tests/profile/w3c_vc/issuer_metadata.json"))
                .unwrap();
    }
}
