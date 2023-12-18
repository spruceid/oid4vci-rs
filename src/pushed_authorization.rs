use std::future::Future;

use crate::{
    authorization::AuthorizationDetail,
    credential::RequestError,
    http_utils::{content_type_has_essence, MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON},
    profiles::AuthorizationDetaislProfile,
    types::ParUrl,
};
use oauth2::{
    http::{
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    AuthUrl, ClientId, CsrfToken, HttpRequest, HttpResponse, PkceCodeChallenge, RedirectUrl,
};
use openidconnect::{core::CoreErrorResponseType, IssuerUrl, Nonce, StandardErrorResponse};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParRequestUri(pub String);

impl ParRequestUri {
    pub fn new_random() -> Self {
        Self(format!(
            "urn:ietf:params:oauth:request_uri:{:}",
            Nonce::new_random().secret().clone()
        ))
    }

    pub fn get(&self) -> &String {
        &self.0
    }
}

pub type Error = StandardErrorResponse<CoreErrorResponseType>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ParAuthParams {
    client_id: ClientId,
    state: CsrfToken,
    code_challenge: String,
    code_challenge_method: String,
    redirect_uri: RedirectUrl,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_assertion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_assertion_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_issuer: Option<IssuerUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer_state: Option<CsrfToken>,
}

impl ParAuthParams {
    field_getters_setters![
        pub self [self] ["ParAuthParams value"] {
            set_client_id -> client_id[ClientId],
            set_state -> state[CsrfToken],
            set_code_challenge -> code_challenge[String],
            set_code_challenge_method -> code_challenge_method[String],
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
    AD: AuthorizationDetaislProfile,
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
    AD: AuthorizationDetaislProfile,
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
        let (url, token) = self.inner.url();

        let query = serde_urlencoded::from_str::<ParAuthParams>(url.clone().as_str())
            .unwrap()
            .set_client_assertion_type(client_assertion_type.clone())
            .set_client_assertion(client_assertion.clone())
            .set_authorization_details(Some(
                serde_json::to_string::<Vec<AuthorizationDetail<AD>>>(&self.authorization_details)
                    .unwrap(),
            ))
            .set_wallet_issuer(self.wallet_issuer)
            .set_user_hint(self.user_hint)
            .set_issuer_state(self.issuer_state);

        let http_request = HttpRequest {
            url: self.par_auth_url.url().clone(),
            method: Method::POST,
            headers: vec![
                (
                    CONTENT_TYPE,
                    HeaderValue::from_static(MIME_TYPE_FORM_URLENCODED),
                ),
                (ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON)),
            ]
            .into_iter()
            .collect(),
            body: serde_json::to_vec(&format!(
                "&{:}&", // had to add & before and after to fix parsing during the request
                serde_urlencoded::to_string(&query).unwrap()
            ))
            .map_err(|e| RequestError::Other(e.to_string()))?,
        };

        let http_response = http_client(http_request)
            .await
            .map_err(RequestError::Request)?;

        if http_response.status_code != StatusCode::OK {
            return Err(RequestError::Response(
                http_response.status_code,
                http_response.body,
                "unexpected HTTP status code".to_string(),
            ));
        }

        let parsed_response: PushedAuthorizationResponse = match http_response
            .headers
            .get(CONTENT_TYPE)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| HeaderValue::from_static(MIME_TYPE_JSON))
        {
            ref content_type if content_type_has_essence(content_type, MIME_TYPE_JSON) => {
                serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(
                    &http_response.body,
                ))
                .map_err(RequestError::Parse)
            }
            ref content_type => Err(RequestError::Response(
                http_response.status_code,
                http_response.body,
                format!("unexpected response Content-Type: `{:?}`", content_type),
            )),
        }?;

        let mut auth_url = self.auth_url.url().clone();

        auth_url
            .query_pairs_mut()
            .append_pair("request_uri", &parsed_response.request_uri.0);

        auth_url
            .query_pairs_mut()
            .append_pair("client_id", &query.client_id.to_string());

        Ok((auth_url, token))
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
