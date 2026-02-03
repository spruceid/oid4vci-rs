use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::issuer::metadata::CredentialFormatMetadata;

use super::W3cVcFormat;

/// Format configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W3cVcFormatMetadata {
    #[serde(rename = "format")]
    pub id: W3cVcFormat,

    pub credential_definition: W3cVcDefinitionMetadata,
}

impl CredentialFormatMetadata for W3cVcFormatMetadata {
    type Format = W3cVcFormat;

    type SigningAlgorithm = String;

    fn id(&self) -> W3cVcFormat {
        self.id
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W3cVcDefinitionMetadata {
    /// Array of JSON-LD contexts.
    ///
    /// Required unless the credential format is [`W3cVcFormat::JwtVcJson`].
    #[serde(rename = "@context")]
    pub context: Option<Vec<json_ld::syntax::ContextEntry>>,

    /// Types supported by the credential.
    pub r#type: Vec<String>,
}

#[cfg(test)]
mod tests {
    use crate::issuer::metadata::CredentialConfigurationsSupported;

    use super::*;

    #[test]
    fn roundtrip() {
        let expected_json: CredentialConfigurationsSupported<W3cVcFormatMetadata> =
            serde_json::from_str(include_str!(
                "../../../tests/profile/w3c_vc/issuer_metadata.json"
            ))
            .unwrap();
        let credential_configuration: CredentialConfigurationsSupported<W3cVcFormatMetadata> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_configuration).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
