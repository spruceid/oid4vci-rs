use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::issuer::metadata::CredentialFormatMetadata;

use super::MsoMdocFormat;

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "format", rename = "mso_mdoc")]
pub struct MsoMdocFormatMetadata {
    pub doctype: String,
}

impl CredentialFormatMetadata for MsoMdocFormatMetadata {
    type Format = MsoMdocFormat;

    type SigningAlgorithm = i64;

    fn id(&self) -> Self::Format {
        MsoMdocFormat
    }
}

#[cfg(test)]
mod tests {
    use crate::issuer::metadata::CredentialConfigurationsSupported;

    use super::*;

    #[test]
    fn roundtrip() {
        let expected_json: CredentialConfigurationsSupported<MsoMdocFormatMetadata> =
            serde_json::from_str(include_str!(
                "../../../tests/profile/mso_mdoc/issuer_metadata.json"
            ))
            .unwrap();
        let credential_configuration: CredentialConfigurationsSupported<MsoMdocFormatMetadata> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_configuration).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
