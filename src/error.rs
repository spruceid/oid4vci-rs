use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[non_exhaustive]
pub enum AuthorizationErrorType {
    #[serde(rename = "invalid_token")]
    InvalidToken,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[non_exhaustive]
pub enum TokenErrorType {
    #[serde(rename = "invalid_request")]
    InvalidRequest,

    #[serde(rename = "invalid_client")]
    InvalidClient,

    #[serde(rename = "invalid_grant")]
    InvalidGrant,

    #[serde(rename = "unauthorized_client")]
    UnauthorizedClient,

    #[serde(rename = "unsupported_grant_type")]
    UnsupportedGrantType,

    #[serde(rename = "invalid_scope")]
    InvalidScope,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[non_exhaustive]
pub enum CredentialRequestErrorType {
    #[serde(rename = "invalid_or_missing_proof")]
    InvalidOrMissingProof,

    #[serde(rename = "invalid_request")]
    InvalidRequest,

    #[serde(rename = "unsupported_type")]
    UnsupportedType,

    #[serde(rename = "unsupported_format")]
    UnsupportedFormat,

    #[serde(rename = "invalid_credential")]
    InvalidCredential,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[non_exhaustive]
#[serde(untagged)]
pub enum OIDCErrorType {
    Authorization(AuthorizationErrorType),
    Token(TokenErrorType),
    CredentialRequest(CredentialRequestErrorType),

    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[non_exhaustive]
pub struct OIDCError {
    #[serde(rename = "error")]
    pub ty: OIDCErrorType,

    #[serde(rename = "error_description")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(rename = "error_uri")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
}

impl OIDCError {
    pub fn with_desc(mut self, description: &str) -> Self {
        self.description = Some(description.to_owned());
        self
    }

    pub fn with_uri(mut self, uri: &str) -> Self {
        self.uri = Some(uri.to_owned());
        self
    }

    pub fn without_desc(mut self) -> Self {
        self.description = None;
        self
    }

    pub fn without_uri(mut self) -> Self {
        self.uri = None;
        self
    }
}

impl Default for OIDCError {
    fn default() -> Self {
        Self {
            ty: OIDCErrorType::Unknown,
            description: None,
            uri: None,
        }
    }
}

impl From<ssi::jws::Error> for OIDCError {
    fn from(_: ssi::jws::Error) -> Self {
        OIDCError {
            ty: OIDCErrorType::CredentialRequest(CredentialRequestErrorType::InvalidRequest),
            description: None,
            uri: None,
        }
    }
}

impl From<ssi::jwk::Error> for OIDCError {
    fn from(_: ssi::jwk::Error) -> Self {
        OIDCError {
            ty: OIDCErrorType::Token(TokenErrorType::InvalidRequest),
            description: None,
            uri: None,
        }
    }
}

impl From<ssi::vc::Error> for OIDCError {
    fn from(_: ssi::vc::Error) -> Self {
        OIDCError {
            ty: OIDCErrorType::Token(TokenErrorType::InvalidRequest),
            description: None,
            uri: None,
        }
    }
}

impl From<serde_json::Error> for OIDCError {
    fn from(_: serde_json::Error) -> Self {
        OIDCError {
            ty: OIDCErrorType::Token(TokenErrorType::InvalidRequest),
            description: None,
            uri: None,
        }
    }
}

impl From<AuthorizationErrorType> for OIDCError {
    fn from(err: AuthorizationErrorType) -> Self {
        OIDCError {
            ty: OIDCErrorType::Authorization(err),
            description: None,
            uri: None,
        }
    }
}

impl AuthorizationErrorType {
    pub fn to_oidcerror(&self, description: Option<String>, uri: Option<String>) -> OIDCError {
        OIDCError {
            ty: OIDCErrorType::Authorization(self.clone()),
            description,
            uri,
        }
    }
}

impl From<TokenErrorType> for OIDCError {
    fn from(err: TokenErrorType) -> Self {
        OIDCError {
            ty: OIDCErrorType::Token(err),
            description: None,
            uri: None,
        }
    }
}

impl TokenErrorType {
    pub fn to_oidcerror(&self, description: Option<String>, uri: Option<String>) -> OIDCError {
        OIDCError {
            ty: OIDCErrorType::Token(self.clone()),
            description,
            uri,
        }
    }
}

impl From<CredentialRequestErrorType> for OIDCError {
    fn from(err: CredentialRequestErrorType) -> Self {
        OIDCError {
            ty: OIDCErrorType::CredentialRequest(err),
            description: None,
            uri: None,
        }
    }
}

impl CredentialRequestErrorType {
    pub fn to_oidcerror(&self, description: Option<String>, uri: Option<String>) -> OIDCError {
        OIDCError {
            ty: OIDCErrorType::CredentialRequest(self.clone()),
            description,
            uri,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_errors() {
        assert_eq!(
            serde_json::to_string(&OIDCError {
                ty: OIDCErrorType::CredentialRequest(
                    CredentialRequestErrorType::InvalidOrMissingProof
                ),
                description: Some(
                    "Credential issuer requires proof element in credential request".into()
                ),
                uri: None,
            })
            .unwrap(),
            r#"{"error":"invalid_or_missing_proof","error_description":"Credential issuer requires proof element in credential request"}"#,
        );
    }
}
