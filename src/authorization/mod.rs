use std::{borrow::Cow, fmt::Debug};

use indexmap::IndexMap;
use iref::Uri;
use oauth2::{CsrfToken, PkceCodeChallenge};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use crate::types::{IssuerState, UserHint};

pub mod pre_authorized_code;
pub mod pushed_authorization;
pub mod server;
pub mod token;

pub struct AuthorizationRequest<'a> {
    inner: oauth2::AuthorizationRequest<'a>,
}

// TODO 5.1.2 scopes

impl<'a> AuthorizationRequest<'a> {
    pub(crate) fn new(inner: oauth2::AuthorizationRequest<'a>) -> Self {
        Self { inner }
    }

    pub fn url(self) -> (Url, CsrfToken) {
        self.inner.url()
    }

    pub fn set_pkce_challenge(mut self, pkce_code_challenge: PkceCodeChallenge) -> Self {
        self.inner = self.inner.set_pkce_challenge(pkce_code_challenge);
        self
    }

    pub fn set_authorization_details<T: CredentialAuthorizationParams>(
        mut self,
        authorization_details: Vec<CredentialAuthorizationDetailsObject<T>>,
    ) -> Result<Self, serde_json::Error> {
        self.inner = self.inner.add_extra_param(
            "authorization_details",
            serde_json::to_string(&authorization_details)?,
        );
        Ok(self)
    }

    pub fn set_issuer_state(mut self, issuer_state: &'a IssuerState) -> Self {
        self.inner = self
            .inner
            .add_extra_param("issuer_state", issuer_state.secret());
        self
    }

    pub fn set_user_hint(mut self, user_hint: &'a UserHint) -> Self {
        self.inner = self.inner.add_extra_param("user_hint", user_hint.secret());
        self
    }

    pub fn set_wallet_issuer(mut self, wallet_issuer: &'a Uri) -> Self {
        self.inner = self
            .inner
            .add_extra_param("wallet_issuer", wallet_issuer.as_str());
        self
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "C: CredentialAuthorizationParams")]
pub struct CredentialAuthorizationDetailsObject<C: CredentialAuthorizationParams> {
    pub r#type: OpenIdCredential,

    #[serde(flatten)]
    pub format_or_configuration: CredentialFormatOrConfigurationId<C::Format>,

    #[serde(flatten)]
    pub params: C,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialFormatOrConfigurationId<F> {
    #[serde(rename = "format")]
    Format(F),

    #[serde(rename = "credential_configuration_id")]
    ConfigurationId(String),
}

/// Credential format authorization details parameters.
///
/// Specifies format-specific parameters in a
/// [`CredentialAuthorizationDetailsObject`].
///
/// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-5.1.1>
pub trait CredentialAuthorizationParams: Debug + Serialize + DeserializeOwned {
    /// Credential format identifier.
    type Format: Debug + Clone + PartialEq + Eq + Serialize + DeserializeOwned;
}

pub type AnyCredentialAuthorizationParams = IndexMap<String, serde_json::Value>;

impl CredentialAuthorizationParams for AnyCredentialAuthorizationParams {
    type Format = String;
}

pub const OPENID_CREDENTIAL: &str = "openid_credential";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenIdCredential;

impl Serialize for OpenIdCredential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        OPENID_CREDENTIAL.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OpenIdCredential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s == OPENID_CREDENTIAL {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("expected \"{OPENID_CREDENTIAL}\""))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use iref::uri;
    use oauth2::{AuthUrl, ClientId, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenUrl};
    use serde_json::json;

    use crate::{
        authorization::server::AuthorizationServerMetadata,
        client::Client,
        issuer::CredentialIssuerMetadata,
        profile::{
            w3c_vc::{W3cVcAuthorizationParams, W3cVcDefinitionAuthorization},
            StandardCredentialAuthorizationParams, StandardFormat, W3cVcFormat,
        },
        types::CredentialUrl,
    };

    use super::*;

    #[test]
    fn example_authorization_details() {
        let _: Vec<CredentialAuthorizationDetailsObject<AnyCredentialAuthorizationParams>> =
            serde_json::from_value(json!([
                {
                  "type": "openid_credential",
                  "format": "jwt_vc_json",
                  "credential_definition": {
                     "type": [
                        "VerifiableCredential",
                        "UniversityDegreeCredential"
                     ]
                  }
               }
            ]))
            .unwrap();
    }

    #[test]
    fn example_authorization_details_credential_configuration_id() {
        let _: Vec<CredentialAuthorizationDetailsObject<AnyCredentialAuthorizationParams>> =
            serde_json::from_value(json!([
                {
                  "type": "openid_credential",
                  "credential_configuration_id": "UniversityDegreeCredential"
                }
            ]))
            .unwrap();
    }

    #[test]
    fn example_authorization_details_locations() {
        let _: Vec<CredentialAuthorizationDetailsObject<AnyCredentialAuthorizationParams>> =
            serde_json::from_value(json!([
                {
                  "type": "openid_credential",
                  "locations": [
                     "https://credential-issuer.example.com"
                  ],
                  "format": "jwt_vc_json",
                  "credential_definition": {
                     "type": [
                        "VerifiableCredential",
                        "UniversityDegreeCredential"
                     ]
                  }
               }
            ]))
            .unwrap();
    }

    #[test]
    fn example_authorization_details_multiple() {
        let _: Vec<CredentialAuthorizationDetailsObject<AnyCredentialAuthorizationParams>> =
            serde_json::from_value(json!([
                {
                  "type":"openid_credential",
                  "format": "ldp_vc",
                  "credential_definition": {
                     "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://www.w3.org/2018/credentials/examples/v1"
                     ],
                     "type": [
                        "VerifiableCredential",
                        "UniversityDegreeCredential"
                     ]
                  }
               },
               {
                  "type":"openid_credential",
                  "format": "mso_mdoc",
                  "doctype":"org.iso.18013.5.1.mDL"
               }
            ]))
            .unwrap();
    }

    #[test]
    fn example_authorization_redirect() {
        // Modifed the code_challenge from the example and added state and removed spaces in authorization_details
        let mut expected_url = Url::try_from("https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&code_challenge=MYdqq2Vt_ZLMAWpXXsjGIrlxrCF2e4ZP4SxDf7cm_tg&code_challenge_method=S256&authorization_details=%5B%7B%22type%22%3A%22openid_credential%22%2C%22format%22%3A%22jwt_vc_json%22%2C%22credential_definition%22%3A%7B%22type%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%7D%5D&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&state=state").unwrap();

        let issuer = uri!("https://server.example.com");

        let credential_issuer_metadata: CredentialIssuerMetadata = CredentialIssuerMetadata::new(
            issuer.to_owned(),
            CredentialUrl::new("https://server.example.com/credential".into()).unwrap(),
        );

        let mut authorization_server_metadata = AuthorizationServerMetadata::new(
            issuer.to_owned(),
            TokenUrl::new("https://server.example.com/token".into()).unwrap(),
        );

        authorization_server_metadata.authorization_endpoint =
            Some(AuthUrl::new("https://server.example.com/authorize".into()).unwrap());

        let client: Client = Client::from_issuer_metadata(
            ClientId::new("s6BhdRkqt3".to_string()),
            RedirectUrl::new("https://client.example.org/cb".into()).unwrap(),
            credential_issuer_metadata,
            authorization_server_metadata,
        );

        let pkce_verifier =
            PkceCodeVerifier::new("challengechallengechallengechallengechallenge".into());
        let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(&pkce_verifier);
        let state = CsrfToken::new("state".into());

        let authorization_detail = StandardCredentialAuthorizationParams {
            w3c_vc: Some(W3cVcAuthorizationParams {
                credential_definition: Some(W3cVcDefinitionAuthorization {
                    r#type: Some(vec![
                        "VerifiableCredential".into(),
                        "UniversityDegreeCredential".into(),
                    ]),
                    ..Default::default()
                }),
            }),
            ..Default::default()
        };

        let authorization_details = vec![CredentialAuthorizationDetailsObject {
            r#type: OpenIdCredential,
            format_or_configuration: CredentialFormatOrConfigurationId::Format(
                StandardFormat::W3c(W3cVcFormat::JwtVcJson),
            ),
            params: authorization_detail,
        }];

        let req = client
            .authorize_url(move || state)
            .unwrap()
            .set_authorization_details(authorization_details)
            .unwrap()
            .set_pkce_challenge(pkce_challenge);

        let (mut url, _) = req.url();
        let expected_query: HashSet<(String, String)> =
            expected_url.query_pairs().into_owned().collect();
        expected_url.set_query(None);
        let query: HashSet<(String, String)> = url.query_pairs().into_owned().collect();
        url.set_query(None);
        assert_eq!(expected_url, url);
        assert_eq!(expected_query, query);
    }
}
