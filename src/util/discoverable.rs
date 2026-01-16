use anyhow::{bail, Context, Result};
use iref::{Uri, UriRef};
use oauth2::{
    http::{self, header::ACCEPT, HeaderValue, Method, StatusCode},
    AsyncHttpClient, HttpRequest, HttpResponse, SyncHttpClient,
};
use serde::de::DeserializeOwned;

use crate::util::http::check_content_type;

use super::http::MIME_TYPE_JSON;

pub trait Discoverable: DeserializeOwned {
    const WELL_KNOWN_URI_REF: &UriRef;

    fn validate(&self, issuer: &Uri) -> Result<()>;

    fn discover<C>(base_url: &Uri, http_client: &C) -> Result<Self>
    where
        C: SyncHttpClient,
        C::Error: Send + Sync,
    {
        let discovery_url = Self::WELL_KNOWN_URI_REF.resolved(base_url);
        let discovery_request = discovery_request(&discovery_url)?;
        let http_response = http_client.call(discovery_request)?;
        discovery_response(base_url, &discovery_url, http_response)
    }

    #[allow(async_fn_in_trait)]
    async fn discover_async<'c, C>(base_url: &Uri, http_client: &'c C) -> Result<Self>
    where
        C: AsyncHttpClient<'c>,
        C::Error: Send + Sync,
    {
        let discovery_url = Self::WELL_KNOWN_URI_REF.resolved(base_url);
        let discovery_request = discovery_request(&discovery_url)?;
        let http_response = http_client.call(discovery_request).await?;
        discovery_response(base_url, &discovery_url, http_response)
    }
}

fn discovery_request(discovery_url: &Uri) -> Result<HttpRequest> {
    http::Request::builder()
        .uri(discovery_url.to_string())
        .method(Method::GET)
        .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
        .body(Vec::new())
        .context("failed to prepare request")
}

fn discovery_response<T: Discoverable>(
    base_url: &Uri,
    discovery_url: &Uri,
    discovery_response: HttpResponse,
) -> Result<T> {
    if discovery_response.status() != StatusCode::OK {
        bail!(
            "HTTP status code {} at {}",
            discovery_response.status(),
            discovery_url
        )
    }

    check_content_type(discovery_response.headers(), MIME_TYPE_JSON)?;

    let metadata = serde_path_to_error::deserialize::<_, T>(
        &mut serde_json::Deserializer::from_slice(discovery_response.body()),
    )?;

    metadata.validate(base_url)?;

    Ok(metadata)
}
