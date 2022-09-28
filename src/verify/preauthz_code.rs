use chrono::prelude::*;

use crate::{
    codec::*,
    error::{OIDCError, TokenErrorType},
    jose::*,
    Metadata, PreAuthzCode,
};

pub fn verify_preauthz_code<I, M>(
    preauthz_code: &str,
    metadata: &M,
    interface: &I,
) -> Result<PreAuthzCode, OIDCError>
where
    I: JOSEInterface<Error = OIDCError>,
    M: Metadata,
{
    let (_, bytes) = interface.jwt_decode_verify(preauthz_code)?;
    let preauthz_code: PreAuthzCode = serde_json::from_slice(&bytes)?;

    let now = Utc::now();
    let expires_at = preauthz_code.expires_at.clone();
    let exp = ToDateTime::from_vcdatetime(expires_at)?;
    if now > exp {
        println!("now({:?}) vs exp({:?})", now, exp);
        return Err(TokenErrorType::InvalidRequest.into());
    }

    let mut supported = metadata.get_credential_types();
    let mut requested = preauthz_code.credential_type.clone().into_iter();

    if !requested.all(|ref req| supported.any(|ref s| s == &req)) {
        return Err(TokenErrorType::InvalidRequest.into());
    }

    Ok(preauthz_code)
}
