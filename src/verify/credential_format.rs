use crate::{
    error::{CredentialRequestErrorType, OIDCError},
    CredentialFormat, Metadata,
};

pub fn verify_allowed_format<M>(
    credential_type: &str,
    format: &Option<CredentialFormat>,
    metadata: &M,
) -> Result<(), OIDCError>
where
    M: Metadata,
{
    match format {
        None => {
            let err: OIDCError = CredentialRequestErrorType::InvalidRequest.into();
            Err(err.with_desc("format must be present"))
        }
        Some(CredentialFormat::Unknown) => {
            let err: OIDCError = CredentialRequestErrorType::UnsupportedFormat.into();
            Err(err.with_desc("unknown format"))
        }
        Some(format) => {
            if !metadata
                .get_allowed_formats(credential_type)
                .any(|f| f == format)
            {
                let err: OIDCError = CredentialRequestErrorType::UnsupportedFormat.into();
                return Err(err.with_desc("unsupported format"));
            }

            Ok(())
        }
    }
}
