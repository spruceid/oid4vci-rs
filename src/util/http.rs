use open_auth2::{
    http::{header, HeaderName, HeaderValue},
    AccessToken,
};

pub const BEARER: &str = "Bearer";

pub fn auth_bearer(access_token: &AccessToken) -> (HeaderName, HeaderValue) {
    (
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("{} {}", BEARER, access_token))
            .expect("invalid access token"),
    )
}
