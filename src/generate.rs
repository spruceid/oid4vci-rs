use std::collections::HashMap;

use chrono::{prelude::*, Duration};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ssi::vc::{NumericDate, VCDateTime};

use crate::{
    codec::*, jose::*, nonce::generate_nonce, CredentialFormat, CredentialRequest,
    CredentialResponse, MaybeUnknownCredentialFormat, PreAuthzCode, Proof, ProofOfPossession,
    TokenResponse, TokenType,
};

pub fn generate_preauthz_code<I, E>(mut params: PreAuthzCode, interface: &I) -> Result<String, E>
where
    E: From<serde_json::Error>,
    I: JOSEInterface<Error = E>,
{
    params.pin = if let Some(pin) = params.pin {
        Some(interface.jwe_encrypt(&pin)?)
    } else {
        None
    };

    let mut claims = serde_json::to_value(params).unwrap();
    let claims = claims.as_object_mut().unwrap();

    claims.insert("nonce".into(), crate::nonce::generate_nonce().into());

    let payload = serde_json::to_string(claims)?;
    interface.jwt_encode_sign(&payload)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct AccessTokenParams {
    // TODO: enable credential_type: Vec<String>,
    // (de)serialize either a single string or Vec of String's
    pub credential_type: String,
    pub op_state: HashMap<String, Value>,
    pub allow_refresh: bool,
    pub token_type: TokenType,
    pub expires_in: u64,
}

impl AccessTokenParams {
    pub fn new(
        credential_type: String,
        op_state: Option<HashMap<String, Value>>,
        token_type: &TokenType,
        expires_in: u64,
    ) -> Self {
        AccessTokenParams {
            credential_type,
            op_state: op_state.unwrap_or_default(),
            allow_refresh: false,
            token_type: token_type.to_owned(),
            expires_in,
        }
    }

    pub fn with_refresh(
        credential_type: String,
        op_state: Option<HashMap<String, Value>>,
        token_type: &TokenType,
        expires_in: u64,
    ) -> Self {
        AccessTokenParams {
            credential_type,
            op_state: op_state.unwrap_or_default(),
            allow_refresh: true,
            token_type: token_type.to_owned(),
            expires_in,
        }
    }
}

pub fn generate_access_token<I, E>(
    AccessTokenParams {
        credential_type,
        mut op_state,
        allow_refresh,
        token_type,
        expires_in,
        ..
    }: AccessTokenParams,
    interface: &I,
) -> Result<TokenResponse, E>
where
    E: From<serde_json::Error>,
    I: JOSEInterface<Error = E>,
{
    let now: crate::Timestamp = VCDateTime::from(Utc::now()).into();
    let exp: crate::Timestamp = VCDateTime::from(Utc::now() + Duration::days(1)).into();

    let now: NumericDate = now.into();
    let exp: NumericDate = exp.into();

    op_state.insert("credential_type".to_string(), credential_type.into());

    let access_token = interface.jwt_encode_sign(&serde_json::to_string(&json!({
        "op_state": op_state,
        "iat": now,
        "exp": exp,
    }))?)?;

    let refresh_token = if allow_refresh {
        Some(interface.jwt_encode_sign(&serde_json::to_string(&json!({
            "op_state": op_state,
            "iat": now,
            "exp": exp,
        }))?)?)
    } else {
        None
    };

    Ok(TokenResponse {
        access_token,
        refresh_token,
        token_type,
        expires_in,
    })
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct IssuanceRequestParams {
    #[serde(rename = "issuer")]
    #[serde(serialize_with = "to_percent_encode")]
    pub issuer: String,

    #[serde(rename = "credential_type")]
    #[serde(serialize_with = "to_percent_encode")]
    pub credential_type: String,

    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,

    #[serde(rename = "user_pin_required")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pin_required: Option<bool>,
}

impl IssuanceRequestParams {
    pub fn new(issuer: &str, credential_type: &str, pre_authorized_code: &str) -> Self {
        Self {
            issuer: issuer.to_owned(),
            credential_type: credential_type.to_owned(),
            pre_authorized_code: pre_authorized_code.to_owned(),
            user_pin_required: None,
        }
    }

    pub fn with_user_pin(
        issuer: &str,
        credential_type: &str,
        pre_authorized_code: &str,
        user_pin_required: bool,
    ) -> Self {
        Self {
            issuer: issuer.to_owned(),
            credential_type: credential_type.to_owned(),
            pre_authorized_code: pre_authorized_code.to_owned(),
            user_pin_required: Some(user_pin_required),
        }
    }
}

pub fn generate_initiate_issuance_request(
    protocol: &str,
    base_url: Option<&str>,
    params: IssuanceRequestParams,
) -> String {
    let params = collect_into_url(&params);

    let base_url = base_url.unwrap_or("");
    let base_url = if !base_url.is_empty() && !base_url.ends_with('/') && !base_url.contains('/') {
        format!("{}/", base_url)
    } else {
        base_url.into()
    };

    format!("{}://{}?{}", protocol, base_url, params)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub struct TokenRequestParams {
    #[serde(rename = "grant_type")]
    pub grant_type: String,

    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,

    #[serde(rename = "user_pin")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pin: Option<String>,
}

pub fn generate_token_request(params: TokenRequestParams) -> String {
    collect_into_url(&params)
}

pub fn generate_credential_request(
    ty: &str,
    format: CredentialFormat,
    proof: Proof,
) -> CredentialRequest {
    CredentialRequest {
        credential_type: Some(ty.into()),
        format: Some(format.into()),
        proof,
    }
}

pub fn generate_proof_of_possession<I, E>(
    issuer: &str,
    audience: &str,
    interface: &I,
) -> Result<Proof, E>
where
    E: From<serde_json::Error>,
    I: JOSEInterface<Error = E>,
{
    let claims = {
        let now = VCDateTime::from(Utc::now());
        let exp = VCDateTime::from(Utc::now() + Duration::minutes(5));

        ProofOfPossession {
            issuer: issuer.into(),
            audience: audience.into(),
            nonce: generate_nonce(),
            not_before: Some(now.clone().into()),
            issued_at: Some(now.into()),
            expires_at: exp.into(),
        }
    };

    let payload = serde_json::to_string(&claims)?;
    let jwt = interface.jwt_encode_sign(&payload)?;

    Ok(Proof::JWT { jwt })
}

pub fn generate_credential_response(
    format: &MaybeUnknownCredentialFormat,
    credential: Value,
) -> CredentialResponse {
    CredentialResponse {
        format: format.to_owned(),
        credential,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_preauthz_code() {}

    #[test]
    fn test_generate_access_token() {}

    #[test]
    fn test_generate_initiate_issuance_request() {
        assert_eq!(
            generate_initiate_issuance_request("https", None, IssuanceRequestParams{
                issuer: "https://oidc4vci.demo.spruceid.com".into(),
                credential_type: "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential".into(),
                pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".into(),
                user_pin_required: None,
            }),
            "https://?\
                issuer=https%3A%2F%2Foidc4vci%2Edemo%2Espruceid%2Ecom\
                &credential_type=https%3A%2F%2Fimsglobal%2Egithub%2Eio%2Fopenbadges%2Dspecification%2Fob%5Fv3p0%2Ehtml%23OpenBadgeCredential\
                &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA"
        );

        assert_eq!(
            generate_initiate_issuance_request("https", None, IssuanceRequestParams{
                issuer: "https://oidc4vci.demo.spruceid.com".into(),
                credential_type: "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential".into(),
                pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".into(),
                user_pin_required: Some(false),
            }),
            "https://?\
                issuer=https%3A%2F%2Foidc4vci%2Edemo%2Espruceid%2Ecom\
                &credential_type=https%3A%2F%2Fimsglobal%2Egithub%2Eio%2Fopenbadges%2Dspecification%2Fob%5Fv3p0%2Ehtml%23OpenBadgeCredential\
                &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA\
                &user_pin_required=false"
        );

        assert_eq!(
            generate_initiate_issuance_request("https", Some(""), IssuanceRequestParams{
                issuer: "https://oidc4vci.demo.spruceid.com".into(),
                credential_type: "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential".into(),
                pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".into(),
                user_pin_required: Some(true),
            }),
            "https://?\
                issuer=https%3A%2F%2Foidc4vci%2Edemo%2Espruceid%2Ecom\
                &credential_type=https%3A%2F%2Fimsglobal%2Egithub%2Eio%2Fopenbadges%2Dspecification%2Fob%5Fv3p0%2Ehtml%23OpenBadgeCredential\
                &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA\
                &user_pin_required=true"
        );

        assert_eq!(
            generate_initiate_issuance_request("https", Some("example.com"), IssuanceRequestParams{
                issuer: "https://oidc4vci.demo.spruceid.com".into(),
                credential_type: "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential".into(),
                pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".into(),
                user_pin_required: Some(false),
            }),
            "https://example.com/?\
                issuer=https%3A%2F%2Foidc4vci%2Edemo%2Espruceid%2Ecom\
                &credential_type=https%3A%2F%2Fimsglobal%2Egithub%2Eio%2Fopenbadges%2Dspecification%2Fob%5Fv3p0%2Ehtml%23OpenBadgeCredential\
                &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA\
                &user_pin_required=false"
        );

        assert_eq!(
            generate_initiate_issuance_request("https", Some("example.com/code"), IssuanceRequestParams{
                issuer: "https://oidc4vci.demo.spruceid.com".into(),
                credential_type: "https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential".into(),
                pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".into(),
                user_pin_required: Some(false),
            }),
            "https://example.com/code?\
                issuer=https%3A%2F%2Foidc4vci%2Edemo%2Espruceid%2Ecom\
                &credential_type=https%3A%2F%2Fimsglobal%2Egithub%2Eio%2Fopenbadges%2Dspecification%2Fob%5Fv3p0%2Ehtml%23OpenBadgeCredential\
                &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA\
                &user_pin_required=false"
        );
    }

    #[test]
    fn test_generate_token_request() {
        assert_eq!(
            generate_token_request(TokenRequestParams {
                grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".into(),
                pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".into(),
                user_pin: None,
            }),
            "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code\
                &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA"
        );
    }

    #[test]
    fn test_generate_credential_request() {}

    #[test]
    fn test_generate_proof_of_possession() {}

    #[test]
    fn test_generate_credential_response() {}
}
