use std::collections::HashMap;

use crate::{
    authorization::AuthorizationDetail,
    core::profiles::CoreProfilesAuthorizationDetails,
    profiles::AuthorizationDetaislProfile,
    proof_of_possession::{
        ConversionError, ParsingError, ProofOfPossessionBody, VerificationError,
    },
};
use oauth2::{AuthUrl, CsrfToken, PkceCodeChallenge};
use openidconnect::{
    core::CoreErrorResponseType, ClientId, IssuerUrl, RedirectUrl, StandardErrorResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::{json::JsonString, serde_as};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParRequestUri(pub String);

impl ParRequestUri {
    pub fn new_random(num_bytes: u32) -> Self {
        use base64::{
            alphabet,
            engine::{self, general_purpose},
            Engine as _,
        };
        use rand::{thread_rng, Rng};

        const CUSTOM_ENGINE: engine::GeneralPurpose =
            engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
        let random_bytes: Vec<u8> = (0..num_bytes).map(|_| thread_rng().gen::<u8>()).collect();
        Self(format!(
            "urn:ietf:params:oauth:request_uri:{:}",
            CUSTOM_ENGINE.encode(random_bytes)
        ))
    }

    pub fn get(&self) -> &String {
        &self.0
    }
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Request {
    redirect_uri: RedirectUrl,
    client_id: ClientId,
    #[serde_as(as = "JsonString")]
    #[serde(rename = "authorization_details")] // TODO unsure what to do with it
    authorization_details: Vec<AuthorizationDetail<CoreProfilesAuthorizationDetails>>,
    state: CsrfToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_uri: Option<String>,
    client_assertion: String,
    client_assertion_type: String,
}

impl Request {
    pub fn client_id(self) -> ClientId {
        self.client_id
    }

    pub fn redirect_uri(self) -> RedirectUrl {
        self.redirect_uri
    }

    pub fn authorization_details(
        self,
    ) -> Vec<AuthorizationDetail<CoreProfilesAuthorizationDetails>> {
        self.authorization_details
    }

    pub fn state(self) -> CsrfToken {
        self.state
    }

    pub fn request_uri(self) -> Option<String> {
        self.request_uri
    }

    pub fn client_assertion_type(self) -> String {
        self.client_assertion_type
    }

    pub fn client_assertion(self) -> String {
        self.client_assertion
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Response {
    request_uri: ParRequestUri,
    expires_in: u64,
}

impl Response {
    pub fn new(request_uri: ParRequestUri, expires_in: u64) -> Self {
        Self {
            request_uri,
            expires_in,
        }
    }

    pub fn request_uri(self) -> ParRequestUri {
        self.request_uri.clone()
    }

    pub fn expires_in(self) -> u64 {
        self.expires_in
    }
}

pub type Error = StandardErrorResponse<CoreErrorResponseType>;

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    iss: String,
    sub: String,
    iat: i64,
    exp: i64,
}

const JWS_TYPE: &str = "openid4vci-proof+jwt";

pub fn make_jwt(
    client_id: String,
    audience: url::Url,
    key_pem: &str,
) -> Result<String, ConversionError> {
    use crate::proof_of_possession::{
        ProofOfPossession, ProofOfPossessionController, ProofOfPossessionParams,
    };
    use ssi::jwk::{ECParams, Params, JWK};
    use time::Duration;

    let key = p256::SecretKey::from_sec1_pem(key_pem).unwrap();
    let jwk = JWK::from(Params::EC(ECParams::try_from(&key).unwrap()));

    let pop_params = ProofOfPossessionParams {
        audience,
        issuer: client_id,
        nonce: None,
        controller: ProofOfPossessionController { vm: None, jwk },
    };
    let pop = ProofOfPossession::generate(&pop_params, Duration::minutes(10));
    let jwt = pop.to_jwt()?;

    Ok(jwt)
}

pub async fn decode_jwt(jwt: String) -> Result<ProofOfPossessionBody, ParsingError> {
    use ssi::{
        jwk::Algorithm,
        jws::{self, Header},
        jwt,
    };

    let header: Header = jws::decode_unverified(jwt.as_str())?.0;

    if header.type_ != Some(JWS_TYPE.to_string()) {
        return Err(ParsingError::InvalidJWSType {
            actual: format!("{:?}", header.type_),
            expected: JWS_TYPE.to_string(),
        });
    }
    if header.algorithm == Algorithm::None {
        return Err(ParsingError::MissingJWSAlg);
    }
    let jwk = match header.jwk {
        Some(jwk) => jwk,
        None => return Err(ParsingError::MissingKeyParameters),
    };
    let decoded_jwt: ProofOfPossessionBody = jwt::decode_verify(jwt.as_str(), &jwk)?;
    Ok(decoded_jwt)
}

pub async fn verify(
    jwt: String,
    client_id: String,
    audience: url::Url,
) -> Result<(), VerificationError> {
    use crate::proof_of_possession::{ProofOfPossession, ProofOfPossessionVerificationParams};
    use did_jwk::DIDJWK;

    let pop = ProofOfPossession::from_jwt(jwt.as_str(), &DIDJWK)
        .await
        .unwrap();

    pop.verify(&ProofOfPossessionVerificationParams {
        nonce: pop.body.nonce.clone(),
        audience,
        issuer: client_id,
        controller_did: None,
        controller_jwk: None,
        nbf_tolerance: None,
        exp_tolerance: None,
    })
    .await
}

pub struct PushedAuthorizationRequest<'a, AD>
where
    AD: AuthorizationDetaislProfile,
{
    inner: oauth2::AuthorizationRequest<'a>, // TODO
    par_auth_url: AuthUrl,
    authorization_details: Vec<AuthorizationDetail<AD>>,
    wallet_issuer: Option<IssuerUrl>, // TODO SIOP related
    user_hint: Option<String>,
    issuer_state: Option<CsrfToken>,
}

impl<'a, AD> PushedAuthorizationRequest<'a, AD>
where
    AD: AuthorizationDetaislProfile,
{
    pub(crate) fn new(
        inner: oauth2::AuthorizationRequest<'a>,
        par_auth_url: AuthUrl,
        authorization_details: Vec<AuthorizationDetail<AD>>,
        wallet_issuer: Option<IssuerUrl>,
        user_hint: Option<String>,
        issuer_state: Option<CsrfToken>,
    ) -> Self {
        Self {
            inner,
            par_auth_url,
            authorization_details,
            wallet_issuer,
            user_hint,
            issuer_state,
        }
    }

    pub fn request(
        self,
        client_assertion_type: String,
        client_assertion: String,
    ) -> Result<(String, serde_json::Value, CsrfToken), serde_json::Error> {
        let (url, token) = self.inner.url();
        let mut body = json!({});
        for (k, v) in url
            .query_pairs()
            .into_owned()
            .collect::<HashMap<String, String>>()
        {
            body.as_object_mut().unwrap().entry(k).or_insert(json!(v));
        }
        body.as_object_mut()
            .unwrap()
            .entry("client_assertion_type")
            .or_insert(json!(client_assertion_type));
        body.as_object_mut()
            .unwrap()
            .entry("client_assertion")
            .or_insert(json!(client_assertion));

        body.as_object_mut()
            .unwrap()
            .entry("authorization_details")
            .or_insert(json!(&serde_json::to_string(&self.authorization_details)?));
        if let Some(w) = self.wallet_issuer {
            body.as_object_mut()
                .unwrap()
                .entry("wallet_issuer")
                .or_insert(json!(&w.to_string()));
        }
        if let Some(h) = self.user_hint {
            body.as_object_mut()
                .unwrap()
                .entry("user_hint")
                .or_insert(json!(&h));
        }
        if let Some(s) = self.issuer_state {
            body.as_object_mut()
                .unwrap()
                .entry("issuer_state")
                .or_insert(json!(s.secret()));
        }
        Ok((self.par_auth_url.to_string(), body, token))
    }

    pub fn set_pkce_challenge(mut self, pkce_code_challenge: PkceCodeChallenge) -> Self {
        self.inner = self.inner.set_pkce_challenge(pkce_code_challenge);
        self
    }
    pub fn set_authorization_details(
        mut self,
        authorization_details: Vec<AuthorizationDetail<AD>>,
    ) -> Self {
        self.authorization_details = authorization_details;
        self
    }
}
