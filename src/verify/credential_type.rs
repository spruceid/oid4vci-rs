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
            .get("credential_type")
            .ok_or(TokenErrorType::InvalidRequest)?
            .to_owned(),
    )?;

    if credential_type.is_none() {
        return Err(CredentialRequestErrorType::InvalidRequest.into());
    }

    let credential_type = credential_type.unwrap();
    if !allowed_credential_types.any(|ref c| c == &credential_type) {
        return Err(CredentialRequestErrorType::UnsupportedType.into());
    }

    Ok(())
}
