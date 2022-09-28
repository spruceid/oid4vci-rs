use crate::{error::OIDCError, jose::*, CredentialRequest, Metadata};

pub async fn verify_credential_request<I, M>(
    CredentialRequest {
        credential_type,
        format,
        proof,
        ..
    }: &CredentialRequest,
    token: &str,
    metadata: &M,
    interface: &I,
) -> Result<String, OIDCError>
where
    I: JOSEInterface<Error = OIDCError>,
    M: Metadata,
{
    let access_token = super::verify_access_token(token, interface)?;
    super::verify_credential_type(credential_type, &access_token)?;
    super::verify_allowed_format(credential_type, format, metadata)?;
    let did = super::verify_proof_of_possession(proof, metadata).await?;

    Ok(did)
}
