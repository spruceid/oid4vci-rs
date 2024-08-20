use std::future::Future;

use crate::{
    authorization::AuthorizationDetail,
    credential::RequestError,
    http_utils::{content_type_has_essence, MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON},
    profiles::AuthorizationDetailsProfile,
    types::ParUrl,
};
use oauth2::{
    http::{
        self,
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    AuthUrl, ClientId, CsrfToken, HttpRequest, HttpResponse, PkceCodeChallenge,
    PkceCodeChallengeMethod, RedirectUrl,
};
use openidconnect::{core::CoreErrorResponseType, IssuerUrl, Nonce, StandardErrorResponse};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParRequestUri(pub String);

impl ParRequestUri {
    pub fn new(nonce: Option<Nonce>) -> Self {
        Self(format!(
            "urn:ietf:params:oauth:request_uri:{:}",
            if let Some(n) = nonce {
                n.secret().clone()
            } else {
                Nonce::new_random().secret().clone()
            }
        ))
    }

    pub fn get(&self) -> &String {
        &self.0
    }
}

pub type Error = StandardErrorResponse<CoreErrorResponseType>;

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParAuthParams {
    client_id: ClientId,
    state: CsrfToken,
    code_challenge: String,
    code_challenge_method: PkceCodeChallengeMethod,
    redirect_uri: RedirectUrl,
    response_type: Option<String>,
    client_assertion: Option<String>,
    client_assertion_type: Option<String>,
    authorization_details: Option<String>,
    wallet_issuer: Option<IssuerUrl>,
    user_hint: Option<String>,
    issuer_state: Option<CsrfToken>,
}

impl ParAuthParams {
    field_getters_setters![
        pub self [self] ["ParAuthParams value"] {
            set_client_id -> client_id[ClientId],
            set_state -> state[CsrfToken],
            set_code_challenge -> code_challenge[String],
            set_code_challenge_method -> code_challenge_method[PkceCodeChallengeMethod],
            set_redirect_uri -> redirect_uri[RedirectUrl],
            set_response_type -> response_type[Option<String>],
            set_client_assertion -> client_assertion[Option<String>],
            set_client_assertion_type -> client_assertion_type[Option<String>],
            set_authorization_details -> authorization_details[Option<String>],
            set_wallet_issuer -> wallet_issuer[Option<IssuerUrl>],
            set_user_hint -> user_hint[Option<String>],
            set_issuer_state -> issuer_state[Option<CsrfToken>],
        }
    ];
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PushedAuthorizationResponse {
    pub request_uri: ParRequestUri,
    pub expires_in: u64,
}

pub struct PushedAuthorizationRequest<'a, AD>
where
    AD: AuthorizationDetailsProfile,
{
    inner: oauth2::AuthorizationRequest<'a>, // TODO
    par_auth_url: ParUrl,
    auth_url: AuthUrl,
    authorization_details: Vec<AuthorizationDetail<AD>>,
    wallet_issuer: Option<IssuerUrl>, // TODO SIOP related
    user_hint: Option<String>,
    issuer_state: Option<CsrfToken>,
}

impl<'a, AD> PushedAuthorizationRequest<'a, AD>
where
    AD: AuthorizationDetailsProfile,
{
    pub(crate) fn new(
        inner: oauth2::AuthorizationRequest<'a>,
        par_auth_url: ParUrl,
        auth_url: AuthUrl,
        authorization_details: Vec<AuthorizationDetail<AD>>,
        wallet_issuer: Option<IssuerUrl>,
        user_hint: Option<String>,
        issuer_state: Option<CsrfToken>,
    ) -> Self {
        Self {
            inner,
            par_auth_url,
            auth_url,
            authorization_details,
            wallet_issuer,
            user_hint,
            issuer_state,
        }
    }

    pub async fn async_request<C, F, RE>(
        self,
        mut http_client: C,
        client_assertion_type: Option<String>,
        client_assertion: Option<String>,
    ) -> Result<(url::Url, CsrfToken), RequestError<RE>>
    where
        C: FnMut(HttpRequest) -> F,
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: std::error::Error + 'static,
    {
        let mut auth_url = self.auth_url.url().clone();

        let (http_request, req_body, token) = self
            .prepare_request(client_assertion, client_assertion_type)
            .map_err(|err| RequestError::Other(format!("failed to prepare request: {err:?}")))?;

        let http_response = http_client(http_request)
            .await
            .map_err(RequestError::Request)?;

        if http_response.status() != StatusCode::OK {
            return Err(RequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                "unexpected HTTP status code".to_string(),
            ));
        }

        let parsed_response: PushedAuthorizationResponse = match http_response
            .headers()
            .get(CONTENT_TYPE)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| HeaderValue::from_static(MIME_TYPE_JSON))
        {
            ref content_type if content_type_has_essence(content_type, MIME_TYPE_JSON) => {
                serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(
                    &http_response.body().to_owned(),
                ))
                .map_err(RequestError::Parse)
            }
            ref content_type => Err(RequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                format!("unexpected response Content-Type: `{:?}`", content_type),
            )),
        }?;

        auth_url
            .query_pairs_mut()
            .append_pair("request_uri", parsed_response.request_uri.get());

        auth_url
            .query_pairs_mut()
            .append_pair("client_id", &req_body.client_id.to_string());

        Ok((auth_url, token))
    }

    pub fn prepare_request(
        self,
        client_assertion: Option<String>,
        client_assertion_type: Option<String>,
    ) -> Result<(HttpRequest, ParAuthParams, CsrfToken), RequestError<http::Error>> {
        let (url, token) = self.inner.url();

        let body = serde_urlencoded::from_str::<ParAuthParams>(url.clone().as_str())
            .map_err(|_| RequestError::Other("failed parsing url".to_string()))?
            .set_client_assertion_type(client_assertion_type.clone())
            .set_client_assertion(client_assertion.clone())
            .set_authorization_details(Some(
                serde_json::to_string::<Vec<AuthorizationDetail<AD>>>(&self.authorization_details)
                    .map_err(|e| {
                        RequestError::Other(format!(
                            "unable to serialize authorization_details: {}",
                            e
                        ))
                    })?,
            ))
            .set_wallet_issuer(self.wallet_issuer)
            .set_user_hint(self.user_hint)
            .set_issuer_state(self.issuer_state);

        let request = http::Request::builder()
            .uri(self.par_auth_url.to_string())
            .method(Method::POST)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static(MIME_TYPE_FORM_URLENCODED),
            )
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .body(
                serde_urlencoded::to_string(&body)
                    .map_err(|e| {
                        RequestError::Other(format!("unable to encode request body: {}", e))
                    })?
                    .as_bytes()
                    .to_vec(),
            )
            .map_err(RequestError::Request)?;
        Ok((request, body, token))
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
    use assert_json_diff::assert_json_eq;
    use oauth2::{AuthUrl, ClientId, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenUrl};
    use serde_json::json;

    use crate::{core::profiles::CoreProfilesAuthorizationDetails, metadata::CredentialUrl};

    use super::*;

    #[test]
    fn example_pushed_authorization_request() {
        let expected_body = json!({
            "client_id": "s6BhdRkqt3",
            "state": "state",
            "code_challenge": "MYdqq2Vt_ZLMAWpXXsjGIrlxrCF2e4ZP4SxDf7cm_tg",
            "code_challenge_method": "S256",
            "redirect_uri": "https://client.example.org/cb",

            "authorization_details": "[]",
        });

        let client = crate::core::client::Client::new(
            ClientId::new("s6BhdRkqt3".to_string()),
            IssuerUrl::new("https://server.example.com".into()).unwrap(),
            CredentialUrl::new("https://server.example.com/credential".into()).unwrap(),
            AuthUrl::new("https://server.example.com/authorize".into()).unwrap(),
            Some(ParUrl::new("https://server.example.com/as/par".into()).unwrap()),
            TokenUrl::new("https://server.example.com/token".into()).unwrap(),
            RedirectUrl::new("https://client.example.org/cb".into()).unwrap(),
        );

        let pkce_verifier =
            PkceCodeVerifier::new("challengechallengechallengechallengechallenge".into());
        let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(&pkce_verifier);
        let state = CsrfToken::new("state".into());

        let (_, body, _) = client
            .pushed_authorization_request::<_, CoreProfilesAuthorizationDetails>(move || state)
            .unwrap()
            .set_pkce_challenge(pkce_challenge)
            .prepare_request(None, None)
            .unwrap();
        assert_json_eq!(expected_body, body);
    }
}
