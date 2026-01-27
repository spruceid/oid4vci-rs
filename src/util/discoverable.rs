use iref::{Uri, UriRef};
use oauth2::{
    http::{self, header::ACCEPT, HeaderValue, Method, StatusCode},
    AsyncHttpClient, HttpRequest, HttpResponse, SyncHttpClient,
};
use serde::de::DeserializeOwned;

use crate::util::http::{check_content_type, HttpError};

use super::http::MIME_TYPE_JSON;

pub trait Discoverable: DeserializeOwned {
    const WELL_KNOWN_URI_REF: &UriRef;

    fn validate(&self, issuer: &Uri) -> Result<(), anyhow::Error>;

    fn discover(http_client: &impl SyncHttpClient, base_url: &Uri) -> Result<Self, HttpError> {
        let discovery_url = Self::WELL_KNOWN_URI_REF.resolved(base_url);
        let discovery_request = discovery_request(&discovery_url);
        let http_response = http_client
            .call(discovery_request)
            .map_err(HttpError::query(base_url))?;
        discovery_response(base_url, http_response)
    }

    #[allow(async_fn_in_trait)]
    async fn discover_async<'c>(
        http_client: &'c impl AsyncHttpClient<'c>,
        base_url: &Uri,
    ) -> Result<Self, HttpError> {
        let discovery_url = Self::WELL_KNOWN_URI_REF.resolved(base_url);
        let discovery_request = discovery_request(&discovery_url);
        let http_response = http_client
            .call(discovery_request)
            .await
            .map_err(HttpError::query(base_url))?;
        discovery_response(base_url, http_response)
    }
}

fn discovery_request(discovery_url: &Uri) -> HttpRequest {
    http::Request::builder()
        .uri(discovery_url.to_string())
        .method(Method::GET)
        .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
        .body(Vec::new())
        // SAFETY: discovery query is always valid.
        .unwrap()
}

fn discovery_response<T: Discoverable>(
    base_url: &Uri,
    discovery_response: HttpResponse,
) -> Result<T, HttpError> {
    let status = discovery_response.status();
    if status != StatusCode::OK {
        return Err(HttpError::ServerError(base_url.to_owned(), status));
    }

    check_content_type(base_url, discovery_response.headers(), MIME_TYPE_JSON)?;

    let metadata: T =
        serde_json::from_slice(discovery_response.body()).map_err(HttpError::json(base_url))?;
    metadata
        .validate(base_url)
        .map_err(HttpError::invalid(base_url))?;

    Ok(metadata)
}
