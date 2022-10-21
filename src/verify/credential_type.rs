use std::collections::HashMap;

use serde_json::Value;
use ssi::one_or_many::OneOrMany;

use crate::error::{CredentialRequestErrorType, OIDCError, TokenErrorType};

pub fn verify_credential_type(
    credential_type: Option<&str>,
    access_token: &HashMap<String, Value>,
) -> Result<(), OIDCError> {
    let allowed_credential_types: OneOrMany<String> = serde_json::from_value(
        access_token
            .get("op_state")
            .ok_or(TokenErrorType::InvalidRequest.into())
            .map_err(|e: OIDCError| e.with_desc("op_state must be present in access_token"))?
            .get("credential_type")
            .ok_or(TokenErrorType::InvalidRequest.into())
            .map_err(|e: OIDCError| e.with_desc("credential_type must be present in op_state"))?
            .to_owned(),
    )?;

    if credential_type.is_none() {
        let err: OIDCError = CredentialRequestErrorType::InvalidRequest.into();
        return Err(err.with_desc("credential_type must not be empty"));
    }

    let credential_type = credential_type.unwrap();
    if !allowed_credential_types.any(|ref c| c == &credential_type) {
        let err: OIDCError = CredentialRequestErrorType::UnsupportedType.into();
        return Err(err.with_desc("credential_type is not supported"));
    }

    Ok(())
}
