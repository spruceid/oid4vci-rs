use crate::{error::OIDCError, jose::*, CredentialRequest, Metadata};

pub type ExternalFormatVerifier = fn(&str) -> bool;

pub async fn verify_credential_request<I, M, F>(
    CredentialRequest {
        credential_type,
        format,
        proof,
        ..
    }: &CredentialRequest,
    token: &str,
    metadata: &M,
    interface: &I,
    external_format_verifier: Option<F>,
) -> Result<String, OIDCError>
where
    I: JOSEInterface<Error = OIDCError>,
    M: Metadata,
    F: FnOnce(&str) -> bool,
{
    let access_token = super::verify_access_token(token, interface)?;

    super::verify_credential_type(credential_type.as_deref(), &access_token)?;

    let credential_type = credential_type.to_owned().unwrap();
    super::verify_allowed_format(&credential_type, format, metadata, external_format_verifier)?;

    let did = super::verify_proof_of_possession(proof, metadata).await?;

    Ok(did)
}
