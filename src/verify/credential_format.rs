use crate::{
    error::{CredentialRequestErrorType, OIDCError},
    MaybeUnknownCredentialFormat, Metadata,
};

macro_rules! unsupported_format {
    () => {{
        let err: OIDCError = CredentialRequestErrorType::UnsupportedFormat.into();
        Err(err.with_desc("unsupported format"))
    }};
}

pub trait ExternalFormatVerifier {
    fn verify(&self, credential_type: &str, format: &str) -> bool;
}

impl ExternalFormatVerifier for () {
    fn verify(&self, _: &str, _: &str) -> bool {
        false
    }
}

pub fn verify_allowed_format<M, F>(
    credential_type: &str,
    format: &Option<MaybeUnknownCredentialFormat>,
    metadata: &M,
    external_verifier: Option<&F>,
) -> Result<(), OIDCError>
where
    M: Metadata,
    F: ExternalFormatVerifier,
{
    match format {
        None => {
            let err: OIDCError = CredentialRequestErrorType::InvalidRequest.into();
            Err(err.with_desc("format must be present"))
        }
        Some(MaybeUnknownCredentialFormat::Unknown(format)) => match external_verifier {
            Some(verifier) => match verifier.verify(credential_type, format) {
                true => Ok(()),
                false => unsupported_format!(),
            },
            None => unsupported_format!(),
        },
        Some(MaybeUnknownCredentialFormat::Known(format)) => {
            if !metadata
                .get_allowed_formats(credential_type)
                .any(|f| f == format)
            {
                return unsupported_format!();
            }

            Ok(())
        }
    }
}
