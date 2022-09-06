use crate::{
    error::{CredentialRequestErrorType, OIDCError},
    CredentialFormat, Metadata,
};

pub fn verify_allowed_format<M>(
    credential_type: &str,
    format: &CredentialFormat,
    metadata: &M,
) -> Result<(), OIDCError>
where
    M: Metadata,
{
    if !metadata
        .get_allowed_formats(credential_type)
        .any(|ref f| f == &format)
    {
        return Err(CredentialRequestErrorType::UnsupportedFormat.into());
    }

    Ok(())
}
