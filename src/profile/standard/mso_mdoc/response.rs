use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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
    serde_json::Value::String(URL_SAFE_NO_PAD.encode(cbor_bytes))
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
    let cbor_bytes = URL_SAFE_NO_PAD
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

#[cfg(test)]
mod tests {
    use super::*;

    /// isomdl's own `IssuerSigned` test vector, 3394 bytes of CBOR as hex.
    const ISSUER_SIGNED_HEX: &str = include_str!("test/issuer_signed.cbor.hex");

    fn issuer_signed_cbor() -> Vec<u8> {
        (0..ISSUER_SIGNED_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&ISSUER_SIGNED_HEX[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn decodes_unpadded_base64url() {
        let cbor = issuer_signed_cbor();
        assert_ne!(
            cbor.len() % 3,
            0,
            "the vector must need padding to test this"
        );
        let value = serde_json::Value::String(URL_SAFE_NO_PAD.encode(&cbor));
        assert!(decode_mso_mdoc(&value).is_ok());
    }

    #[test]
    fn encodes_without_padding() {
        let value = serde_json::Value::String(URL_SAFE_NO_PAD.encode(issuer_signed_cbor()));
        let issuer_signed = decode_mso_mdoc(&value).ok().unwrap();
        let encoded = encode_mso_mdoc(&issuer_signed);
        assert!(!encoded.as_str().unwrap().contains('='));
        assert!(decode_mso_mdoc(&encoded).is_ok());
    }
}
