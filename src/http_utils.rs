use anyhow::{bail, Result};
use oauth2::{
    http::{
        header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
        HeaderName,
    },
    AccessToken,
};

pub const MIME_TYPE_JSON: &str = "application/json";
pub const MIME_TYPE_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

pub const BEARER: &str = "Bearer";

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

pub fn check_content_type(headers: &HeaderMap, expected_content_type: &str) -> Result<()> {
    headers
        .get(CONTENT_TYPE)
        .map_or(Ok(()), |content_type|
            // Section 3.1.1.1 of RFC 7231 indicates that media types are case insensitive and
            // may be followed by optional whitespace and/or a parameter (e.g., charset).
            // See https://tools.ietf.org/html/rfc7231#section-3.1.1.1.
            if !content_type_has_essence(content_type, expected_content_type) {
                    bail!(
                        "Unexpected response Content-Type: {:?}, should be `{}`",
                        content_type,
                        expected_content_type
                    )
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
