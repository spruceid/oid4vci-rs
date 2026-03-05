use base64::{engine::general_purpose::URL_SAFE, Engine};
use isomdl::definitions::IssuerSigned;

/// Encodes an [`IssuerSigned`] mdoc object as [`CredentialResponse`]
/// `credential` JSON value.
///
/// The object will be encoded as CBOR, then base64.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.2.4>
///
/// [`CredentialResponse`]: crate::endpoints::credential::CredentialResponse
pub fn encode_mso_mdoc(input: &IssuerSigned) -> serde_json::Value {
    let cbor_bytes = isomdl::cbor::to_vec(input)
        // UNWRAP SAFETY: `IssuerSigned` can be encoded as CBOR.
        .unwrap();
    serde_json::Value::String(URL_SAFE.encode(cbor_bytes))
}

/// Decodes a [`IssuerSigned`] mdoc object from a [`CredentialResponse`]
/// `credential` JSON value.
///
/// The value is expected to be a base64 string encoding the object as CBOR.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.2.4>
///
/// [`CredentialResponse`]: crate::endpoints::credential::CredentialResponse
pub fn decode_mso_mdoc(input: &serde_json::Value) -> Result<IssuerSigned, InvalidMsoMdoc> {
    let cbor_bytes = URL_SAFE
        .decode(input.as_str().ok_or(InvalidMsoMdoc::NotAString)?)
        .map_err(InvalidMsoMdoc::Base64)?;
    isomdl::cbor::from_slice(&cbor_bytes).map_err(InvalidMsoMdoc::Cbor)
}

/// Error returned by [`decode_mso_mdoc`].
pub enum InvalidMsoMdoc {
    /// The input value was not a JSON string.
    NotAString,

    /// The input value was not a valid base64 string.
    Base64(base64::DecodeError),

    /// The decoded base64 string was not a valid [`IssuerSigned`] CBOR object.
    Cbor(isomdl::cbor::CborError),
}
