#![allow(clippy::type_complexity)]

use std::future::Future;

use anyhow::{bail, Context, Result};
use oauth2::{
    http::{self, header::ACCEPT, HeaderValue, Method, StatusCode},
    AsyncHttpClient, HttpRequest, HttpResponse, SyncHttpClient,
};
use serde::{de::DeserializeOwned, Serialize};
use url::Url;

use crate::{
    http_utils::{check_content_type, MIME_TYPE_JSON},
    types::IssuerUrl,
};

pub mod authorization_server;
pub mod credential_issuer;

pub use authorization_server::AuthorizationServerMetadata;
pub use credential_issuer::CredentialIssuerMetadata;

pub trait MetadataDiscovery: DeserializeOwned + Serialize {
    const METADATA_URL_SUFFIX: &'static str;

    fn validate(&self, issuer: &IssuerUrl) -> Result<()>;

    fn discover<C>(issuer: &IssuerUrl, http_client: &C) -> Result<Self>
    where
        C: SyncHttpClient,
        C::Error: Send + Sync,
    {
        let discovery_url = discovery_url::<Self>(issuer)?;

        let discovery_request = discovery_request(&discovery_url)?;

        let http_response = http_client.call(discovery_request)?;

        discovery_response(issuer, &discovery_url, http_response)
    }

    fn discover_async<'c, C>(
        issuer: &IssuerUrl,
        http_client: &'c C,
    ) -> impl Future<Output = Result<Self>>
    where
        C: AsyncHttpClient<'c>,
        C::Error: Send + Sync,
    {
        Box::pin(async move {
            let discovery_url = discovery_url::<Self>(issuer)?;

            let discovery_request = discovery_request(&discovery_url)?;

            let http_response = http_client.call(discovery_request).await?;

            discovery_response(issuer, &discovery_url, http_response)
        })
    }
}

fn discovery_url<M: MetadataDiscovery>(issuer: &IssuerUrl) -> Result<Url> {
    issuer
        .join(M::METADATA_URL_SUFFIX)
        .context("failed to construct metadata URL")
}

fn discovery_request(discovery_url: &Url) -> Result<HttpRequest> {
    http::Request::builder()
        .uri(discovery_url.to_string())
        .method(Method::GET)
        .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
        .body(Vec::new())
        .context("failed to prepare request")
}

fn discovery_response<M: MetadataDiscovery>(
    issuer: &IssuerUrl,
    discovery_url: &Url,
    discovery_response: HttpResponse,
) -> Result<M> {
    if discovery_response.status() != StatusCode::OK {
        bail!(
            "HTTP status code {} at {}",
            discovery_response.status(),
            discovery_url
        )
    }

    check_content_type(discovery_response.headers(), MIME_TYPE_JSON)?;

    let metadata = serde_path_to_error::deserialize::<_, M>(
        &mut serde_json::Deserializer::from_slice(discovery_response.body()),
    )?;

    metadata.validate(issuer)?;

    Ok(metadata)
}
