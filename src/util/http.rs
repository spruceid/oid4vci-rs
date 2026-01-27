use anyhow::Result;
use iref::{Uri, UriBuf};
use oauth2::{
    http::{
        header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
        HeaderName, StatusCode,
    },
    AccessToken,
};

pub const MIME_TYPE_JSON: &str = "application/json";
pub const MIME_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

pub const BEARER: &str = "Bearer";

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("query at `{0}` failed: {1}")]
    Query(UriBuf, String),

    #[error("server at `{0}` responded with status code {1}")]
    ServerError(UriBuf, StatusCode),

    #[error("unexpected response `Content-Type` header value from `{uri}` (expected `{expected}`, found `{found:?}`)")]
    ContentType {
        uri: UriBuf,
        expected: String,
        found: HeaderValue,
    },

    #[error("unable to decode JSON body from `{0}`: {1}")]
    Json(UriBuf, serde_json::Error),

    #[error("invalid response from `{0}`: {0}")]
    Invalid(UriBuf, String),
}

impl HttpError {
    pub fn query<'a, E>(uri: &'a Uri) -> impl use<'a, E> + FnOnce(E) -> Self
    where
        E: ToString,
    {
        |e| Self::Query(uri.to_owned(), e.to_string())
    }

    pub fn json<'a>(uri: &'a Uri) -> impl use<'a> + FnOnce(serde_json::Error) -> Self {
        |e| Self::Json(uri.to_owned(), e)
    }

    pub fn invalid<'a, E>(uri: &'a Uri) -> impl use<'a, E> + FnOnce(E) -> Self
    where
        E: ToString,
    {
        |e| Self::Invalid(uri.to_owned(), e.to_string())
    }
}

// The [essence](https://mimesniff.spec.whatwg.org/#mime-type-essence) is the <type>/<subtype>
// representation.
pub fn content_type_has_essence(content_type: &HeaderValue, expected_essence: &str) -> bool {
    #[allow(clippy::or_fun_call)]
    content_type
        .to_str()
        .ok()
        .filter(|ct| {
            ct[..ct.find(';').unwrap_or(ct.len())].to_lowercase() == expected_essence.to_lowercase()
        })
        .is_some()
}

pub fn check_content_type(uri: &Uri, headers: &HeaderMap, expected: &str) -> Result<(), HttpError> {
    headers
        .get(CONTENT_TYPE)
        .map_or(Ok(()), |content_type|
            // Section 3.1.1.1 of RFC 7231 indicates that media types are case insensitive and
            // may be followed by optional whitespace and/or a parameter (e.g., charset).
            // See https://tools.ietf.org/html/rfc7231#section-3.1.1.1.
            if !content_type_has_essence(content_type, expected) {
                Err(HttpError::ContentType { uri: uri.to_owned(), expected: expected.to_owned(), found: content_type.clone() })
            } else {
                Ok(())
            }
        )
}

pub fn auth_bearer(access_token: &AccessToken) -> (HeaderName, HeaderValue) {
    (
        AUTHORIZATION,
        HeaderValue::from_str(&format!("{} {}", BEARER, access_token.secret()))
            .expect("invalid access token"),
    )
}
