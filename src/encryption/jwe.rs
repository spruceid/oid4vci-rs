use serde::{Deserialize, Serialize};

/// JWE Algorithm.
///
/// See: <https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.1>
/// See: <https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Algorithm {
    #[serde(untagged)]
    Other(String),
}

/// JWE Content Encryption Algorithm.
///
/// See: <https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.2>
/// See: <https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum EncryptionAlgorithm {
    #[serde(untagged)]
    Other(String),
}

/// JWE Compression Algorithm.
///
/// See: <https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3>
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CompressionAlgorithm {
    /// [RFC 1951] DEFLATE.
    ///
    /// [RFC 1951]: <https://www.rfc-editor.org/rfc/rfc1951>
    #[serde(rename = "DEF")]
    Def,

    /// Unknown compression algorithm.
    #[serde(untagged)]
    Other(String),
}
