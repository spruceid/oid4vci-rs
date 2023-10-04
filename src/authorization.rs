use openidconnect::{CsrfToken, IssuerUrl};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::credential_profiles::AuthorizationDetaislProfile;

pub struct AuthorizationRequest<'a, AD>
where
    AD: AuthorizationDetaislProfile,
{
    inner: oauth2::AuthorizationRequest<'a>, // TODO
    authorization_details: Vec<AuthorizationDetail<AD>>,
    wallet_issuer: Option<IssuerUrl>, // TODO SIOP related
    user_hint: Option<String>,
    issuer_state: Option<CsrfToken>,
}

// TODO 5.1.2 scopes

impl<'a, AD> AuthorizationRequest<'a, AD>
where
    AD: AuthorizationDetaislProfile,
{
    pub fn url(self) -> Result<(Url, CsrfToken), serde_json::Error> {
        let (mut url, token) = self.inner.url();
        url.query_pairs_mut().append_pair(
            "authorization_details",
            &serde_json::to_string(&self.authorization_details)?,
        );
        if let Some(w) = self.wallet_issuer {
            url.query_pairs_mut()
                .append_pair("wallet_issuer", &w.to_string());
        }
        if let Some(h) = self.user_hint {
            url.query_pairs_mut().append_pair("user_hint", &h);
        }
        if let Some(s) = self.issuer_state {
            url.query_pairs_mut()
                .append_pair("issuer_state", s.secret());
        }
        Ok((url, token))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuthorizationDetail<AD>
where
    AD: AuthorizationDetaislProfile,
{
    r#type: AuthorizationDetailType,
    #[serde(flatten, bound = "AD: AuthorizationDetaislProfile")]
    addition_profile_fields: AD,
    #[serde(skip_serializing_if = "Option::is_none")]
    locations: Option<Vec<IssuerUrl>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDetailType {
    OpenidCredential,
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use oauth2::{
        basic::BasicClient, AuthUrl, ClientId, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    };
    use serde_json::json;

    use crate::credential_profiles::{w3c, CoreProfilesAuthorizationDetails};

    use super::*;

    #[test]
    fn example_authorization_details() {
        let _: Vec<AuthorizationDetail<CoreProfilesAuthorizationDetails>> =
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
    fn example_authorization_details_locations() {
        let _: Vec<AuthorizationDetail<CoreProfilesAuthorizationDetails>> =
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
        let _: Vec<AuthorizationDetail<CoreProfilesAuthorizationDetails>> =
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

        let oauth2_client = BasicClient::new(
            ClientId::new("s6BhdRkqt3".to_string()),
            None,
            AuthUrl::new("https://server.example.com/authorize".into()).unwrap(),
            None,
        )
        .set_redirect_uri(RedirectUrl::new("https://client.example.org/cb".into()).unwrap());

        let pkce_verifier =
            PkceCodeVerifier::new("challengechallengechallengechallengechallenge".into());
        let pkce_challenge = PkceCodeChallenge::from_code_verifier_sha256(&pkce_verifier);
        let state = CsrfToken::new("state".into());
        let oauth2_req = oauth2_client
            .authorize_url(move || state)
            .set_pkce_challenge(pkce_challenge);
        let req = AuthorizationRequest {
            inner: oauth2_req,
            authorization_details: vec![AuthorizationDetail {
                r#type: AuthorizationDetailType::OpenidCredential,
                addition_profile_fields: CoreProfilesAuthorizationDetails::JWTVC(
                    w3c::jwt::AuthorizationDetails::new(w3c::CredentialDefinition::new(vec![
                        "VerifiableCredential".into(),
                        "UniversityDegreeCredential".into(),
                    ])),
                ),
                locations: None,
            }],
            wallet_issuer: None,
            user_hint: None,
            issuer_state: None,
        };
        let (mut url, _) = req.url().unwrap();
        let expected_query: HashSet<(String, String)> =
            expected_url.query_pairs().into_owned().collect();
        expected_url.set_query(None);
        let query: HashSet<(String, String)> = url.query_pairs().into_owned().collect();
        url.set_query(None);
        assert_eq!(expected_url, url);
        assert_eq!(expected_query, query);
    }
}
