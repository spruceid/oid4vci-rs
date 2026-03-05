//! Credential Offer types and methods.
//!
//! See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4>
#![allow(clippy::large_enum_variant, deprecated)]

use std::str::FromStr;

use iref::{
    uri::{Query, QueryBuf, SchemeBuf},
    Uri, UriBuf,
};
use open_auth2::{
    client::OAuth2ClientError,
    http,
    transport::{expect_content_type, HttpClient, APPLICATION_JSON},
};
use pct_str::{PctString, URIReserved};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};

mod grant;

pub use grant::*;

/// Credential Offer-related errors.
#[derive(Debug, thiserror::Error)]
pub enum CredentialOfferError {
    #[error(transparent)]
    OAuth2(#[from] OAuth2ClientError),

    #[error("credential offer is not an URI")]
    InvalidUri,

    /// Credential Offer could not be decoded.
    #[error("could not decode credential offer: {0}")]
    Decoding(String),
}

/// Credential Offer.
///
/// Provides the Credential Offer parameters by value, or by reference.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CredentialOffer {
    #[serde(rename = "credential_offer")]
    Value(CredentialOfferParameters),

    #[serde(rename = "credential_offer_uri")]
    /// URL using the https scheme referencing a resource containing a JSON
    /// object with the Credential Offer parameters.
    Reference(UriBuf),
}

impl CredentialOffer {
    /// Scheme of a URI encoded credential offer.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-openid-credential-offer>
    pub const SCHEME: &str = "openid-credential-offer";

    /// Decodes a URI-encoded Credential Offer.
    ///
    /// In such URL, the `credential_offer` parameter is encoded as a string
    /// that must be parsed as a JSON object.
    pub fn from_uri(uri: &Uri) -> Result<Self, CredentialOfferError> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum EncodedCredentialOffer {
            Value { credential_offer: String },
            Reference { credential_offer_uri: UriBuf },
        }

        match serde_urlencoded::from_bytes(uri.query().map(Query::as_bytes).unwrap_or_default())
            .map_err(|e| CredentialOfferError::Decoding(e.to_string()))?
        {
            EncodedCredentialOffer::Reference {
                credential_offer_uri: uri,
            } => Ok(CredentialOffer::Reference(uri)),
            EncodedCredentialOffer::Value {
                credential_offer: params,
            } => Ok(CredentialOffer::Value(
                serde_json::from_str(
                    &params, // &percent_encoding::percent_decode_str(&params)
                            // .decode_utf8()
                            // .context("could not percent decode credential offer JSON")?,
                )
                .map_err(|e| CredentialOfferError::Decoding(e.to_string()))?,
            )),
        }
    }

    /// Creates a URI-encoded credential offer.
    pub fn to_uri(&self) -> UriBuf {
        let mut result = UriBuf::from_scheme(
            SchemeBuf::new(Self::SCHEME.to_owned().into_bytes())
                // SAFETY: `Self::SCHEME` is a valid scheme.
                .unwrap(),
        );

        let query = match self {
            Self::Value(params) => {
                let json = serde_json::to_string(params)
                    // SAFETY: `CredentialOfferParameters` is always encodable as JSON.
                    .unwrap();

                let pct_encoded = PctString::encode(json.chars(), InvalidUriChars);

                QueryBuf::new(format!("credential_offer={pct_encoded}").into_bytes())
                    // SAFETY: the input string is always a valid query thanks
                    //         to percent encoding.
                    .unwrap()
            }
            Self::Reference(uri) => {
                let pct_encoded = PctString::encode(uri.chars(), URIReserved);
                QueryBuf::new(format!("credential_offer_uri={pct_encoded}").into_bytes())
                    // SAFETY: the input string is always a valid query thanks
                    //         to percent encoding.
                    .unwrap()
            }
        };

        result.set_query(Some(&query));
        result
    }

    /// Resolves this credential offer into its parameters, asynchronously.
    ///
    /// This will either return the `credential_offer` value, or dereference the
    /// `credential_offer_uri` URL.
    pub async fn resolve(
        self,
        http_client: &impl HttpClient,
    ) -> Result<CredentialOfferParameters, CredentialOfferError> {
        match self {
            CredentialOffer::Value(params) => Ok(params),
            CredentialOffer::Reference(uri) => {
                let request = Self::build_request(&uri);
                let response = http_client.send(request).await?;
                Self::handle_response(response).map_err(Into::into)
            }
        }
    }

    fn build_request(url: &Uri) -> http::Request<Vec<u8>> {
        http::Request::builder()
            .uri(url.as_str())
            .method(http::Method::GET)
            .header(http::header::ACCEPT, APPLICATION_JSON)
            .body(Vec::new())
            // SAFETY: Request is always valid.
            .unwrap()
    }

    fn handle_response(
        response: http::Response<Vec<u8>>,
    ) -> Result<CredentialOfferParameters, OAuth2ClientError> {
        let status = response.status();
        if status != http::StatusCode::OK {
            return Err(OAuth2ClientError::ServerError(status));
        }

        expect_content_type(response.headers(), &APPLICATION_JSON)?;
        serde_json::from_slice(response.body()).map_err(OAuth2ClientError::response)
    }
}

impl FromStr for CredentialOffer {
    type Err = CredentialOfferError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri = Uri::new(s).map_err(|_| CredentialOfferError::InvalidUri)?;
        Self::from_uri(uri)
    }
}

struct InvalidUriChars;

impl pct_str::Encoder for InvalidUriChars {
    fn encode(&self, c: char) -> bool {
        !c.is_ascii_alphanumeric() || matches!(c, '{' | '}') || URIReserved.encode(c)
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
    pub credential_issuer: UriBuf,

    /// Offered credential configurations.
    ///
    /// Each configuration id must match a key in
    /// [`CredentialIssuerMetadata::credential_configurations_supported`].
    ///
    /// This array must not be empty.
    ///
    /// [`CredentialIssuerMetadata::credential_configurations_supported`]: crate::issuer::CredentialIssuerMetadata::credential_configurations_supported
    pub credential_configuration_ids: Vec<String>, // TODO enforce non-emptiness.

    /// Grant Types the Credential Issuer's Authorization Server is prepared to
    /// process for this Credential Offer.
    #[serde(default, skip_serializing_if = "CredentialOfferGrants::is_empty")]
    pub grants: CredentialOfferGrants,
}

impl CredentialOfferParameters {
    /// Create new Credential Offer parameters.
    pub fn new(
        credential_issuer: UriBuf,
        credential_configuration_ids: Vec<String>,
        grants: CredentialOfferGrants,
    ) -> Self {
        Self {
            credential_issuer,
            credential_configuration_ids,
            grants,
        }
    }
}

#[cfg(feature = "axum")]
mod axum {
    use ::axum::{
        body::Body,
        http::header::CONTENT_TYPE,
        response::{IntoResponse, Response},
    };
    use open_auth2::transport::APPLICATION_JSON;

    use super::*;

    impl IntoResponse for CredentialOfferParameters {
        fn into_response(self) -> Response {
            Response::builder()
                .status(http::StatusCode::OK)
                .header(CONTENT_TYPE, APPLICATION_JSON)
                .body(Body::from(serde_json::to_vec(&self).unwrap()))
                .unwrap()
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn from_uri() {
        let uri = Uri::new(b"openid-credential-offer:?credential_offer_uri=http%3A%2F%2F127.0.0.1%3A3000%2Foffer%2FW6FFMNcNkPbw0fcqsOjS8wyon5LqJQ").unwrap();
        CredentialOffer::from_uri(uri).unwrap();
    }

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
