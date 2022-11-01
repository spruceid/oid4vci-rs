use std::collections::HashMap;

use chrono::prelude::*;
use serde_json::Value;
use ssi::vc::NumericDate;

use crate::{
    error::{AuthorizationErrorType, OIDCError, TokenErrorType},
    jose::*,
};

pub fn verify_access_token<I>(
    token: &str,
    interface: &I,
) -> Result<HashMap<String, Value>, OIDCError>
where
    I: JOSEInterface<Error = OIDCError>,
{
    let (_, access_token) = interface.jwt_decode_verify(token)?;
    let access_token: HashMap<String, Value> = serde_json::from_slice(&access_token)?;

    let iat = access_token
        .get("iat")
        .ok_or_else(|| TokenErrorType::InvalidRequest.into())
        .map_err(|e: OIDCError| e.with_desc("iat must be present"))?
        .as_f64()
        .ok_or_else(|| TokenErrorType::InvalidRequest.into())
        .map_err(|e: OIDCError| e.with_desc("iat must be in numeric date format"))?;

    let iat = NumericDate::try_from_seconds(iat)
        .map_err(|_| TokenErrorType::InvalidRequest.into())
        .map_err(|e: OIDCError| e.with_desc("iat is not a valid numeric date"))?;

    let exp = access_token
        .get("exp")
        .ok_or_else(|| TokenErrorType::InvalidRequest.into())
        .map_err(|e: OIDCError| e.with_desc("exp must be present"))?
        .as_f64()
        .ok_or_else(|| TokenErrorType::InvalidRequest.into())
        .map_err(|e: OIDCError| e.with_desc("exp must be in numeric date format"))?;

    let exp = NumericDate::try_from_seconds(exp)
        .map_err(|_| TokenErrorType::InvalidRequest.into())
        .map_err(|e: OIDCError| e.with_desc("exp is not a valid numeric date"))?;

    let now: NumericDate = Utc::now().try_into().unwrap();

    if now < iat {
        return Err(AuthorizationErrorType::InvalidToken.into());
    }

    if now > exp {
        return Err(AuthorizationErrorType::InvalidToken.into());
    }

    Ok(access_token)
}
