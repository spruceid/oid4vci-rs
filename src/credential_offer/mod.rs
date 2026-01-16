//! Credential Offer types and methods.
//!
//! See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4>
#![allow(clippy::large_enum_variant, deprecated)]

use anyhow::{bail, Context, Result};
use oauth2::{
    http::{self, header::ACCEPT, HeaderValue, Method, StatusCode},
    AsyncHttpClient, SyncHttpClient,
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use url::Url;

use crate::{
    http_utils::{check_content_type, MIME_TYPE_JSON},
    types::{CredentialConfigurationId, CredentialOfferRequest, IssuerUrl},
};

mod grant;

pub use grant::*;

/// Credential Offer.
///
/// Provides the Credential Offer parameters by value, or by reference.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CredentialOffer {
    Value {
        /// Object with the Credential Offer parameters.
        credential_offer: CredentialOfferParameters,
    },

    Reference {
        /// URL using the https scheme referencing a resource containing a JSON
        /// object with the Credential Offer parameters.
        credential_offer_uri: Url,
    },
}

impl CredentialOffer {
    /// Decodes a Credential Offer from an URL.
    ///
    /// In such URL, the `credential_offer` parameter is encoded as a string
    /// that must be parsed as a JSON object.
    pub fn from_request(uri: CredentialOfferRequest) -> Result<Self> {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(untagged)]
        enum EncodedCredentialOffer {
            Value { credential_offer: String },
            Reference { credential_offer_uri: Url },
        }

        match serde_path_to_error::deserialize(serde_urlencoded::Deserializer::new(
            form_urlencoded::parse(uri.url().query().unwrap_or_default().as_bytes()),
        ))? {
            EncodedCredentialOffer::Reference {
                credential_offer_uri,
            } => Ok(CredentialOffer::Reference {
                credential_offer_uri,
            }),
            EncodedCredentialOffer::Value { credential_offer } => Ok(CredentialOffer::Value {
                credential_offer: serde_json::from_str(
                    &percent_encoding::percent_decode_str(&credential_offer)
                        .decode_utf8()
                        .context("could not percent decode credential offer JSON")?,
                )
                .context("could not decode inner JSON")?,
            }),
        }
    }

    /// Resolves this credential offer into its parameters.
    ///
    /// This will either return the `credential_offer` value, or dereference the
    /// `credential_offer_uri` URL.
    pub fn resolve<C>(self, http_client: &C) -> Result<CredentialOfferParameters>
    where
        C: SyncHttpClient,
        C::Error: Send + Sync,
    {
        let uri = match self {
            CredentialOffer::Value { credential_offer } => return Ok(credential_offer),
            CredentialOffer::Reference {
                credential_offer_uri,
            } => credential_offer_uri,
        };

        let request = Self::build_request(&uri)?;

        let response = http_client
            .call(request)
            .context("error occurred when making the request")?;

        Self::handle_response(response, &uri)
    }

    /// Resolves this credential offer into its parameters, asynchronously.
    ///
    /// This will either return the `credential_offer` value, or dereference the
    /// `credential_offer_uri` URL.
    pub async fn resolve_async<'c, C>(self, http_client: &'c C) -> Result<CredentialOfferParameters>
    where
        C: AsyncHttpClient<'c>,
        C::Error: Send + Sync,
    {
        let uri = match self {
            CredentialOffer::Value { credential_offer } => return Ok(credential_offer),
            CredentialOffer::Reference {
                credential_offer_uri,
            } => credential_offer_uri,
        };

        let request = Self::build_request(&uri)?;

        let response = http_client
            .call(request)
            .await
            .context("error occurred when making the request")?;

        Self::handle_response(response, &uri)
    }

    fn build_request(url: &Url) -> Result<http::Request<Vec<u8>>> {
        http::Request::builder()
            .uri(url.as_str())
            .method(Method::GET)
            .header(ACCEPT, HeaderValue::from_static(MIME_TYPE_JSON))
            .body(Vec::new())
            .context("failed to prepare request")
    }

    fn handle_response(
        response: http::Response<Vec<u8>>,
        url: &Url,
    ) -> Result<CredentialOfferParameters> {
        if response.status() != StatusCode::OK {
            bail!("HTTP status code {} at {}", response.status(), url)
        }

        check_content_type(response.headers(), MIME_TYPE_JSON)?;

        serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_slice(response.body()))
            .context("failed to parse response body")
    }
}

/// Credential Offer Parameters.
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1>
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialOfferParameters {
    /// URL of the Credential Issuer from which the Wallet is requested to
    /// obtain one or more Credentials.
    pub credential_issuer: IssuerUrl,

    /// Offered credential configurations.
    ///
    /// Each configuration id must match a key in
    /// [`CredentialIssuerMetadata::credential_configurations_supported`].
    ///
    /// This array must not be empty.
    pub credential_configuration_ids: Vec<CredentialConfigurationId>, // TODO enforce non-emptiness.

    /// Grant Types the Credential Issuer's Authorization Server is prepared to
    /// process for this Credential Offer.
    #[serde(default, skip_serializing_if = "CredentialOfferGrants::is_empty")]
    pub grants: CredentialOfferGrants,
}

impl CredentialOfferParameters {
    /// Create new Credential Offer parameters.
    pub fn new(
        credential_issuer: IssuerUrl,
        credential_configuration_ids: Vec<CredentialConfigurationId>,
        grants: CredentialOfferGrants,
    ) -> Self {
        Self {
            credential_issuer,
            credential_configuration_ids,
            grants,
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn example_credential_offer_object() {
        let _: CredentialOfferParameters = serde_json::from_value(json!({
           "credential_issuer": "https://credential-issuer.example.com",
           "credential_configuration_ids": [
              "UniversityDegreeCredential",
              "org.iso.18013.5.1.mDL"
           ],
           "grants": {
              "authorization_code": {
                 "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
              },
              "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                 "pre-authorized_code": "adhjhdjajkdkhjhdj",
                 "tx_code": {
                   "length": 4,
                   "input_mode": "numeric",
                   "description": "Please provide the one-time code that was sent via e-mail"
                 }
              }
           }
        }))
        .unwrap();
    }
}
