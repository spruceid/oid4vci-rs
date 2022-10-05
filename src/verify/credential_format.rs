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
        None => Err(CredentialRequestErrorType::InvalidRequest.into()),
        Some(CredentialFormat::Unknown) => {
            Err(CredentialRequestErrorType::UnsupportedFormat.into())
        }
        Some(format) => {
            if !metadata
                .get_allowed_formats(credential_type)
                .any(|f| f == format)
            {
                return Err(CredentialRequestErrorType::UnsupportedFormat.into());
            }

            Ok(())
        }
    }
}
