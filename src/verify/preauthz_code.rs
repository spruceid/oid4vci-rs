use chrono::prelude::*;

use crate::{
    codec::*,
    error::{OIDCError, TokenErrorType},
    jose::*,
    Metadata, PreAuthzCode,
};

#[cfg(feature = "encryption")]
pub fn verify_preauthz_code<I, M>(
    preauthz_code: &str,
    user_pin: Option<&str>,
    metadata: &M,
    interface: &I,
) -> Result<PreAuthzCode, OIDCError>
where
    I: JOSEInterface<Error = OIDCError>,
    M: Metadata,
{
    let (_, bytes) = interface
        .jwt_decode_verify(preauthz_code)
        .map_err(|_| TokenErrorType::InvalidGrant)?;

    let preauthz_code: PreAuthzCode =
        serde_json::from_slice(&bytes).map_err(|_| TokenErrorType::InvalidGrant)?;

    let now = Utc::now();
    let expires_at = preauthz_code.expires_at.clone();
    let exp = ToDateTime::from_vcdatetime(expires_at).map_err(|_| TokenErrorType::InvalidGrant)?;
    if now > exp {
        return Err(TokenErrorType::InvalidRequest.into());
    }

    let mut supported = metadata.get_credential_types();
    let mut requested = preauthz_code.credential_type.clone().into_iter();

    if !requested.all(|ref req| supported.any(|ref s| s == &req)) {
        return Err(TokenErrorType::InvalidRequest.into());
    }

    match (&preauthz_code.pin, user_pin) {
        (Some(enc), Some(rhs)) => {
            let lhs = interface.jwe_decrypt(enc)?;
            if lhs != rhs {
                Err(TokenErrorType::InvalidGrant.into())
            } else {
                Ok(preauthz_code)
            }
        }
        (None, Some(_)) => Err(TokenErrorType::InvalidGrant.into()),
        (Some(_), None) => Err(TokenErrorType::InvalidGrant.into()),
        (None, None) => Ok(preauthz_code),
    }
}
