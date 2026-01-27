use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::issuer::metadata::CredentialFormatMetadata;

use super::DcSdJwtFormat;

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "format", rename = "dc+sd-jwt")]
pub struct DcSdJwtFormatMetadata {
    pub vct: String,
}

impl CredentialFormatMetadata for DcSdJwtFormatMetadata {
    type Format = DcSdJwtFormat;

    type SigningAlgorithm = String;

    fn id(&self) -> Self::Format {
        DcSdJwtFormat
    }
}

#[cfg(test)]
mod tests {
    use crate::issuer::metadata::CredentialConfigurationsSupported;

    use super::*;

    #[test]
    fn roundtrip() {
        let expected_json: CredentialConfigurationsSupported<DcSdJwtFormatMetadata> =
            serde_json::from_str(include_str!(
                "../../../tests/profile/dc_sd_jwt/issuer_metadata.json"
            ))
            .unwrap();
        let credential_configuration: CredentialConfigurationsSupported<DcSdJwtFormatMetadata> =
            serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_str(
                &serde_json::to_string(&expected_json).unwrap(),
            ))
            .unwrap();

        let roundtripped = serde_json::to_value(credential_configuration).unwrap();
        assert_json_diff::assert_json_eq!(expected_json, roundtripped)
    }
}
