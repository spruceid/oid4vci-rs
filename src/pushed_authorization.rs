use std::{borrow::Cow, collections::HashMap, future::Future};

use crate::{
    authorization::{AuthorizationDetail, AuthorizationRequest},
    credential::RequestError,
    http_utils::{content_type_has_essence, MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON},
    profiles::AuthorizationDetailsProfile,
    types::{IssuerState, IssuerUrl, Nonce, ParUrl, UserHint},
};
use oauth2::{
    http::{
        self,
        header::{ACCEPT, CONTENT_TYPE},
        HeaderValue, Method, StatusCode,
    },
    AsyncHttpClient, AuthUrl, ClientId, CsrfToken, HttpRequest, PkceCodeChallenge,
    PkceCodeChallengeMethod, RedirectUrl, SyncHttpClient,
};
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

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ParAuthParams {
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
    #[serde(flatten)]
    additional_fields: HashMap<String, String>,
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
    inner: AuthorizationRequest<'a, AD>,
    par_auth_url: ParUrl,
    auth_url: AuthUrl,
}

impl<'a, AD> PushedAuthorizationRequest<'a, AD>
where
    AD: AuthorizationDetailsProfile,
{
    pub(crate) fn new(
        inner: AuthorizationRequest<'a, AD>,
        par_auth_url: ParUrl,
        auth_url: AuthUrl,
    ) -> Self {
        Self {
            inner,
            par_auth_url,
            auth_url,
        }
    }

    pub fn request<C>(
        self,
        http_client: &C,
    ) -> Result<(url::Url, CsrfToken), RequestError<<C as SyncHttpClient>::Error>>
    where
        C: SyncHttpClient,
    {
        let mut auth_url = self.auth_url.url().clone();

        let (http_request, req_body, token) = self
            .prepare_request()
            .map_err(|err| RequestError::Other(format!("failed to prepare request: {err:?}")))?;

        let http_response = http_client
            .call(http_request)
            .map_err(RequestError::Request)?;

        let parsed_response = Self::parse_response(http_response)?;

        auth_url
            .query_pairs_mut()
            .append_pair("request_uri", parsed_response.request_uri.get());

        auth_url
            .query_pairs_mut()
            .append_pair("client_id", &req_body.client_id.to_string());

        Ok((auth_url, token))
    }

    pub fn async_request<'c, C>(
        self,
        http_client: &'c C,
    ) -> impl Future<
        Output = Result<(url::Url, CsrfToken), RequestError<<C as AsyncHttpClient<'c>>::Error>>,
    > + 'c
    where
        'a: 'c,
        C: AsyncHttpClient<'c>,
        AD: 'c,
    {
        Box::pin(async move {
            let mut auth_url = self.auth_url.url().clone();

            let (http_request, req_body, token) = self.prepare_request().map_err(|err| {
                RequestError::Other(format!("failed to prepare request: {err:?}"))
            })?;

            let http_response = http_client
                .call(http_request)
                .await
                .map_err(RequestError::Request)?;

            let parsed_response = Self::parse_response(http_response)?;

            auth_url
                .query_pairs_mut()
                .append_pair("request_uri", parsed_response.request_uri.get());

            auth_url
                .query_pairs_mut()
                .append_pair("client_id", &req_body.client_id.to_string());

            Ok((auth_url, token))
        })
    }

    fn prepare_request(
        self,
    ) -> Result<(HttpRequest, ParAuthParams, CsrfToken), RequestError<http::Error>> {
        let (url, token) = self.inner.url();

        let body = serde_urlencoded::from_str::<ParAuthParams>(url.query().unwrap_or_default())
            .map_err(|_| RequestError::Other("failed parsing url".to_string()))?;

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

    fn parse_response<RE: std::error::Error>(
        http_response: http::Response<Vec<u8>>,
    ) -> Result<PushedAuthorizationResponse, RequestError<RE>> {
        if http_response.status() != StatusCode::OK {
            return Err(RequestError::Response(
                http_response.status(),
                http_response.body().to_owned(),
                "unexpected HTTP status code".to_string(),
            ));
        }

        match http_response
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
        }
    }

    pub fn set_pkce_challenge(mut self, pkce_code_challenge: PkceCodeChallenge) -> Self {
        self.inner = self.inner.set_pkce_challenge(pkce_code_challenge);
        self
    }

    pub fn set_authorization_details(
        mut self,
        authorization_details: Vec<AuthorizationDetail<AD>>,
    ) -> Result<Self, serde_json::Error> {
        self.inner = self
            .inner
            .set_authorization_details(authorization_details)?;
        Ok(self)
    }

    pub fn set_issuer_state(mut self, issuer_state: &'a IssuerState) -> Self {
        self.inner = self.inner.set_issuer_state(issuer_state);
        self
    }

    pub fn set_user_hint(mut self, user_hint: &'a UserHint) -> Self {
        self.inner = self.inner.set_user_hint(user_hint);
        self
    }

    pub fn set_wallet_issuer(mut self, wallet_issuer: &'a IssuerUrl) -> Self {
        self.inner = self.inner.set_wallet_issuer(wallet_issuer);
        self
    }

    pub fn set_client_assertion(self, client_assertion: String) -> Self {
        self.add_extra_param("client_assertion", client_assertion)
    }

    pub fn set_client_assertion_type(self, client_assertion_type: String) -> Self {
        self.add_extra_param("client_assertion_type", client_assertion_type)
    }

    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.inner = self.inner.add_extra_param(name, value);
        self
    }
}

#[cfg(test)]
mod test {
    use assert_json_diff::assert_json_eq;
    use oauth2::{AuthUrl, ClientId, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenUrl};
    use serde_json::json;

    use crate::{
        core::{metadata::CredentialIssuerMetadata, profiles::CoreProfilesAuthorizationDetails},
        metadata::AuthorizationServerMetadata,
        types::CredentialUrl,
    };

    use super::*;

    #[test]
    fn example_pushed_authorization_request() {
        let expected_body = json!({
            "client_id": "s6BhdRkqt3",
            "state": "state",
            "code_challenge": "MYdqq2Vt_ZLMAWpXXsjGIrlxrCF2e4ZP4SxDf7cm_tg",
            "code_challenge_method": "S256",
            "redirect_uri": "https://client.example.org/cb",
            "response_type": "code",
            "authorization_details": "[]",
        });

        let issuer = IssuerUrl::new("https://server.example.com".into()).unwrap();

        let credential_issuer_metadata = CredentialIssuerMetadata::new(
            issuer.clone(),
            CredentialUrl::new("https://server.example.com/credential".into()).unwrap(),
        );

        let authorization_server_metadata = AuthorizationServerMetadata::new(
            issuer,
            TokenUrl::new("https://server.example.com/token".into()).unwrap(),
        )
        .set_authorization_endpoint(Some(
            AuthUrl::new("https://server.example.com/authorize".into()).unwrap(),
        ))
        .set_pushed_authorization_request_endpoint(Some(
            ParUrl::new("https://server.example.com/as/par".into()).unwrap(),
        ));

        let client = crate::core::client::Client::from_issuer_metadata(
            ClientId::new("s6BhdRkqt3".to_string()),
            RedirectUrl::new("https://client.example.org/cb".into()).unwrap(),
            credential_issuer_metadata,
            authorization_server_metadata,
        );

        let pkce_verifier =
            PkceCodeVerifier::new("challengechallengechallengechallengechallenge".into());
        let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(&pkce_verifier);
        let state = CsrfToken::new("state".into());

        let (_, body, _) = client
            .pushed_authorization_request::<_, CoreProfilesAuthorizationDetails>(move || state)
            .unwrap()
            .set_pkce_challenge(pkce_challenge)
            .set_authorization_details(vec![])
            .unwrap()
            .prepare_request()
            .unwrap();
        assert_json_eq!(expected_body, body);
    }
}
