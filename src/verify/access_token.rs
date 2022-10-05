use std::collections::HashMap;

use chrono::prelude::*;
use serde_json::Value;

use crate::{
    codec::*,
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

    let iat = ToDateTime::from_str(
        access_token
            .get("iat")
            .ok_or(TokenErrorType::InvalidRequest)?
            .as_str()
            .ok_or(TokenErrorType::InvalidRequest)?,
    )?;

    let exp = ToDateTime::from_str(
        access_token
            .get("exp")
            .ok_or(TokenErrorType::InvalidRequest)?
            .as_str()
            .ok_or(TokenErrorType::InvalidRequest)?,
    )?;

    let now = Utc::now();

    if now < iat {
        return Err(AuthorizationErrorType::InvalidToken.into());
    }

    if now > exp {
        return Err(AuthorizationErrorType::InvalidToken.into());
    }

    Ok(access_token)
}
