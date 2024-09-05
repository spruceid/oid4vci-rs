use std::{borrow::Cow, error::Error, future::Future, marker::PhantomData};

use base64::prelude::*;
use oauth2::{
    http::{
        self,
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, StatusCode,
    },
    AsyncHttpClient, AuthType, ClientId, ClientSecret, ErrorResponse, HttpRequest, HttpResponse,
    RequestTokenError, Scope, SyncHttpClient, TokenResponse, TokenUrl,
};
use serde::de::DeserializeOwned;
use url::Url;

use crate::{
    http_utils::{MIME_TYPE_FORM_URLENCODED, MIME_TYPE_JSON},
    types::{PreAuthorizedCode, TxCode},
};

/// A request to exchange an authorization code for an access token.
///
/// See <https://tools.ietf.org/html/rfc6749#section-4.1.3>.
#[derive(Debug)]
pub struct PreAuthorizedCodeTokenRequest<'a, TE, TR>
where
    TE: ErrorResponse,
    TR: TokenResponse,
{
    pub(crate) auth_type: &'a AuthType,
    pub(crate) client_id: Option<&'a ClientId>,
    pub(crate) client_secret: Option<&'a ClientSecret>,
    pub(crate) code: PreAuthorizedCode,
    pub(crate) extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub(crate) token_url: &'a TokenUrl,
    pub(crate) tx_code: Option<&'a TxCode>,
    pub(crate) _phantom: PhantomData<(TE, TR)>,
}
impl<'a, TE, TR> PreAuthorizedCodeTokenRequest<'a, TE, TR>
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
{
    /// Appends an extra param to the token request.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    pub fn set_tx_code(mut self, tx_code: &'a TxCode) -> Self {
        self.tx_code = Some(tx_code);
        self
    }

    pub fn set_anonymous_client(mut self) -> Self {
        self.client_id = None;
        self
    }

    fn prepare_request<RE>(self) -> Result<HttpRequest, RequestTokenError<RE, TE>>
    where
        RE: Error + 'static,
    {
        let mut params = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            ),
            ("pre-authorized_code", self.code.secret()),
        ];

        if let Some(tx_code) = self.tx_code {
            params.push(("tx_code", tx_code.secret()))
        }

        endpoint_request(
            self.auth_type,
            self.client_id,
            self.client_secret,
            &self.extra_params,
            None,
            self.token_url.url(),
            params,
        )
        .map_err(|err| RequestTokenError::Other(format!("failed to prepare request: {err}")))
    }

    /// Synchronously sends the request to the authorization server and awaits a response.
    pub fn request<C>(
        self,
        http_client: &C,
    ) -> Result<TR, RequestTokenError<<C as SyncHttpClient>::Error, TE>>
    where
        C: SyncHttpClient,
    {
        endpoint_response(http_client.call(self.prepare_request()?)?)
    }

    /// Asynchronously sends the request to the authorization server and returns a Future.
    pub fn request_async<'c, C>(
        self,
        http_client: &'c C,
    ) -> impl Future<Output = Result<TR, RequestTokenError<<C as AsyncHttpClient<'c>>::Error, TE>>> + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
    {
        Box::pin(async move { endpoint_response(http_client.call(self.prepare_request()?).await?) })
    }
}

#[allow(clippy::too_many_arguments)]
fn endpoint_request<'a>(
    auth_type: &'a AuthType,
    client_id: Option<&'a ClientId>,
    client_secret: Option<&'a ClientSecret>,
    extra_params: &'a [(Cow<'a, str>, Cow<'a, str>)],
    scopes: Option<&'a Vec<Cow<'a, Scope>>>,
    url: &'a Url,
    params: Vec<(&'a str, &'a str)>,
) -> Result<HttpRequest, http::Error> {
    let mut builder = http::Request::builder()
        .uri(url.to_string())
        .method(http::Method::POST)
        .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static(MIME_TYPE_FORM_URLENCODED),
        );

    let scopes_opt = scopes.and_then(|scopes| {
        if !scopes.is_empty() {
            Some(
                scopes
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        } else {
            None
        }
    });

    let mut params: Vec<(&str, &str)> = params;
    if let Some(ref scopes) = scopes_opt {
        params.push(("scope", scopes));
    }

    if let Some(client_id) = client_id {
        match (auth_type, client_secret) {
            // Basic auth only makes sense when a client secret is provided. Otherwise, always pass the
            // client ID in the request body.
            (AuthType::BasicAuth, Some(secret)) => {
                // Section 2.3.1 of RFC 6749 requires separately url-encoding the id and secret
                // before using them as HTTP Basic auth username and password. Note that this is
                // not standard for ordinary Basic auth, so curl won't do it for us.
                let urlencoded_id: String =
                    form_urlencoded::byte_serialize(client_id.as_bytes()).collect();
                let urlencoded_secret: String =
                    form_urlencoded::byte_serialize(secret.secret().as_bytes()).collect();
                let b64_credential =
                    BASE64_STANDARD.encode(format!("{}:{}", &urlencoded_id, urlencoded_secret));
                builder = builder.header(
                    AUTHORIZATION,
                    HeaderValue::from_str(&format!("Basic {}", &b64_credential)).unwrap(),
                );
            }
            (AuthType::RequestBody, _) | (AuthType::BasicAuth, None) => {
                params.push(("client_id", client_id));
                if let Some(client_secret) = client_secret {
                    params.push(("client_secret", client_secret.secret()));
                }
            }
            (_, _) => (),
        }
    }

    params.extend_from_slice(
        extra_params
            .iter()
            .map(|(k, v)| (k.as_ref(), v.as_ref()))
            .collect::<Vec<_>>()
            .as_slice(),
    );

    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish()
        .into_bytes();

    builder.body(body)
}

fn endpoint_response<RE, TE, DO>(
    http_response: HttpResponse,
) -> Result<DO, RequestTokenError<RE, TE>>
where
    RE: Error,
    TE: ErrorResponse,
    DO: DeserializeOwned,
{
    check_response_status(&http_response)?;

    check_response_body(&http_response)?;

    let response_body = http_response.body().as_slice();
    serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(response_body))
        .map_err(|e| RequestTokenError::Parse(e, response_body.to_vec()))
}

fn check_response_status<RE, TE>(
    http_response: &HttpResponse,
) -> Result<(), RequestTokenError<RE, TE>>
where
    RE: Error + 'static,
    TE: ErrorResponse,
{
    if http_response.status() != StatusCode::OK {
        let reason = http_response.body().as_slice();
        if reason.is_empty() {
            Err(RequestTokenError::Other(
                "server returned empty error response".to_string(),
            ))
        } else {
            let error = match serde_path_to_error::deserialize::<_, TE>(
                &mut serde_json::Deserializer::from_slice(reason),
            ) {
                Ok(error) => RequestTokenError::ServerResponse(error),
                Err(error) => RequestTokenError::Parse(error, reason.to_vec()),
            };
            Err(error)
        }
    } else {
        Ok(())
    }
}

fn check_response_body<RE, TE>(
    http_response: &HttpResponse,
) -> Result<(), RequestTokenError<RE, TE>>
where
    RE: Error + 'static,
    TE: ErrorResponse,
{
    // Validate that the response Content-Type is JSON.
    http_response
    .headers()
    .get(CONTENT_TYPE)
    .map_or(Ok(()), |content_type|
      // Section 3.1.1.1 of RFC 7231 indicates that media types are case-insensitive and
      // may be followed by optional whitespace and/or a parameter (e.g., charset).
      // See https://tools.ietf.org/html/rfc7231#section-3.1.1.1.
      if content_type.to_str().ok().filter(|ct| ct.to_lowercase().starts_with(MIME_TYPE_JSON)).is_none() {
        Err(
          RequestTokenError::Other(
            format!(
              "unexpected response Content-Type: {:?}, should be `{}`",
              content_type,
              MIME_TYPE_JSON
            )
          )
        )
      } else {
        Ok(())
      }
    )?;

    if http_response.body().is_empty() {
        return Err(RequestTokenError::Other(
            "server returned empty response body".to_string(),
        ));
    }

    Ok(())
}
