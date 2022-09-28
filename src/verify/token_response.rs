use crate::{error::OIDCError, jose::*, TokenResponse};

pub fn verify_token_response<I>(token: &str, interface: &I) -> Result<TokenResponse, OIDCError>
where
    I: JOSEInterface<Error = OIDCError>,
{
    let (_, bytes) = interface.jwt_decode_verify(token)?;
    Ok(serde_json::from_slice(&bytes)?)
}
