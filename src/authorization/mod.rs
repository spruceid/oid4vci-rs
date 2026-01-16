use std::borrow::Cow;

use iref::{Uri, UriBuf};
use oauth2::{CsrfToken, PkceCodeChallenge};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    profiles::AuthorizationDetailsObjectProfile,
    types::{IssuerState, UserHint},
};

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

    pub fn set_authorization_details<AD: AuthorizationDetailsObjectProfile>(
        mut self,
        authorization_details: Vec<AuthorizationDetailsObject<AD>>,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetailsObject<AD>
where
    AD: AuthorizationDetailsObjectProfile,
{
    pub r#type: AuthorizationDetailsObjectType,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<UriBuf>,
    #[serde(flatten, bound = "AD: AuthorizationDetailsObjectProfile")]
    pub additional_profile_fields: AD,
}

impl<AD> AuthorizationDetailsObject<AD>
where
    AD: AuthorizationDetailsObjectProfile,
{
    pub fn new(additional_profile_fields: AD) -> Self {
        Self {
            r#type: AuthorizationDetailsObjectType::OpenidCredential,
            locations: Vec::new(),
            additional_profile_fields,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum AuthorizationDetailsObjectType {
    #[default]
    #[serde(rename = "openid_credential")]
    OpenidCredential,
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use iref::uri;
    use oauth2::{AuthUrl, ClientId, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenUrl};
    use serde_json::json;

    use crate::{
        authorization::server::AuthorizationServerMetadata,
        profiles::core::{
            metadata::CredentialIssuerMetadata,
            profiles::{jwt_vc_json, CoreProfilesAuthorizationDetailsObject},
        },
        types::CredentialUrl,
    };

    use super::*;

    #[test]
    fn example_authorization_details() {
        let _: Vec<AuthorizationDetailsObject<CoreProfilesAuthorizationDetailsObject>> =
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
        let _: Vec<AuthorizationDetailsObject<CoreProfilesAuthorizationDetailsObject>> =
            serde_json::from_value(json!([
                {
                  "type": "openid_credential",
                  "credential_configuration_id": "UniversityDegreeCredential"
                }
            ]))
            .unwrap();
    }

    #[test]
    fn example_authorization_details_credential_configuration_id_deny() {
        assert!(serde_json::from_value::<
            Vec<AuthorizationDetailsObject<CoreProfilesAuthorizationDetailsObject>>,
        >(json!([
            {
              "type": "openid_credential",
              "format": "jwt_vc_json",
              "credential_configuration_id": "UniversityDegreeCredential"
            }
        ]))
        .is_err());
    }

    #[test]
    fn example_authorization_details_locations() {
        let _: Vec<AuthorizationDetailsObject<CoreProfilesAuthorizationDetailsObject>> =
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
        let _: Vec<crate::profiles::core::authorization::AuthorizationDetailsObject> =
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

        let credential_issuer_metadata = CredentialIssuerMetadata::new(
            issuer.to_owned(),
            CredentialUrl::new("https://server.example.com/credential".into()).unwrap(),
        );

        let mut authorization_server_metadata = AuthorizationServerMetadata::new(
            issuer.to_owned(),
            TokenUrl::new("https://server.example.com/token".into()).unwrap(),
        );

        authorization_server_metadata.authorization_endpoint =
            Some(AuthUrl::new("https://server.example.com/authorize".into()).unwrap());

        let client = crate::profiles::core::client::Client::from_issuer_metadata(
            ClientId::new("s6BhdRkqt3".to_string()),
            RedirectUrl::new("https://client.example.org/cb".into()).unwrap(),
            credential_issuer_metadata,
            authorization_server_metadata,
        );

        let pkce_verifier =
            PkceCodeVerifier::new("challengechallengechallengechallengechallenge".into());
        let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(&pkce_verifier);
        let state = CsrfToken::new("state".into());

        let mut authorization_detail = jwt_vc_json::AuthorizationDetailsObjectWithFormat::default();
        authorization_detail.credential_definition.r#type = vec![
            "VerifiableCredential".into(),
            "UniversityDegreeCredential".into(),
        ];

        let authorization_details = vec![AuthorizationDetailsObject {
            r#type: AuthorizationDetailsObjectType::OpenidCredential,
            additional_profile_fields: CoreProfilesAuthorizationDetailsObject::WithFormat {
                inner:
                    crate::profiles::core::profiles::AuthorizationDetailsObjectWithFormat::JwtVcJson(
                        authorization_detail,
                    ),
                _credential_identifier: (),
            },
            locations: vec![],
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
