use crate::{error::OIDCError, jose::*};

// This is wrong, a Token Response is plain json. But I don't see it used anywhere.
#[deprecated = "Deserialize token::Response instead"]
#[allow(deprecated)]
pub fn verify_token_response<I>(
    token: &str,
    interface: &I,
) -> Result<crate::TokenResponse, OIDCError>
where
    I: JOSEInterface<Error = OIDCError>,
{
    let (_, bytes) = interface.jwt_decode_verify(token)?;
    Ok(serde_json::from_slice(&bytes)?)
}
