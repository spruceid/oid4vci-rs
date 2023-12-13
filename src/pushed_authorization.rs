use std::collections::HashMap;

use crate::{
    authorization::AuthorizationDetail,
    profiles::AuthorizationDetaislProfile,
    proof_of_possession::{
        ConversionError, ParsingError, ProofOfPossessionBody, VerificationError,
    },
};
use oauth2::{AuthUrl, CsrfToken, PkceCodeChallenge};
use openidconnect::{core::CoreErrorResponseType, IssuerUrl, StandardErrorResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

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

pub type Error = StandardErrorResponse<CoreErrorResponseType>;

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
        client_assertion_type: Option<String>,
        client_assertion: Option<String>,
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

#[cfg(test)]
mod test {
    use assert_json_diff::assert_json_include;
    use oauth2::{AuthUrl, ClientId, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenUrl};

    use crate::{core::profiles::CoreProfilesAuthorizationDetails, metadata::CredentialUrl};

    use super::*;

    #[test]
    fn example_pushed_authorization_request() {
        let expected_par_auth_url = "https://server.example.com/as/par";
        let expected_body = json!({
            "authorization_details": "[]",
            "client_assertion": null,
            "client_assertion_type": null,
            "client_id": "s6BhdRkqt3",
            "code_challenge": "MYdqq2Vt_ZLMAWpXXsjGIrlxrCF2e4ZP4SxDf7cm_tg",
            "code_challenge_method": "S256",
            "redirect_uri": "https://client.example.org/cb",
            "response_type": "code",
            "state": "state"
        });
        let expected_auth_url =
            "https://server.example.com/authorize?request_uri=request_uri&client_id=s6BhdRkqt3";

        let client = crate::core::client::Client::new(
            ClientId::new("s6BhdRkqt3".to_string()),
            IssuerUrl::new("https://server.example.com".into()).unwrap(),
            CredentialUrl::new("https://server.example.com/credential".into()).unwrap(),
            AuthUrl::new("https://server.example.com/authorize".into()).unwrap(),
            Some(AuthUrl::new("https://server.example.com/as/par".into()).unwrap()),
            TokenUrl::new("https://server.example.com/token".into()).unwrap(),
            RedirectUrl::new("https://client.example.org/cb".into()).unwrap(),
        );

        let pkce_verifier =
            PkceCodeVerifier::new("challengechallengechallengechallengechallenge".into());
        let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(&pkce_verifier);
        let state = CsrfToken::new("state".into());

        let (par_auth_url, body, _) = client
            .pushed_authorization_request::<_, CoreProfilesAuthorizationDetails>(move || state)
            .unwrap()
            .set_pkce_challenge(pkce_challenge)
            .request(None, None)
            .unwrap();

        let auth_url = client.pushed_authorize_url("request_uri".to_string());

        assert_eq!(expected_par_auth_url, par_auth_url.as_str());
        assert_json_include!(actual: expected_body, expected: body);
        assert_eq!(expected_auth_url, auth_url);
    }
}
