use openidconnect::{CsrfToken, IssuerUrl, Scope};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};
use url::Url;

use crate::credential_profiles::CredentialOfferProfile;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CredentialOffer<CO>
where
    CO: CredentialOfferProfile,
{
    Value {
        #[serde(bound = "CO: CredentialOfferProfile")]
        credential_offer: CredentialOfferParameters<CO>,
    },
    Reference {
        credential_offer_uri: Url,
    },
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialOfferParameters<CO>
where
    CO: CredentialOfferProfile,
{
    credential_issuer: IssuerUrl,
    #[serde(bound = "CO: CredentialOfferProfile")]
    credentials: Vec<CredentialOfferFormat<CO>>,
    grants: Option<CredentialOfferGrants>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CredentialOfferFormat<CO>
where
    CO: CredentialOfferProfile,
{
    Reference(Scope),
    #[serde(bound = "CO: CredentialOfferProfile")]
    Value(CO),
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialOfferGrants {
    authorization_code: Option<AuthorizationCodeGrant>,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pre_authorized_code: Option<PreAuthorizationCodeGrant>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationCodeGrant {
    issuer_state: Option<CsrfToken>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreAuthorizationCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pre_authorized_code: String,
    user_pin_required: Option<bool>,
    interval: Option<usize>,
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::credential_profiles::CoreProfilesOffer;

    use super::*;

    #[test]
    fn example_credential_offer_object() {
        let _: CredentialOfferParameters<CoreProfilesOffer> = serde_json::from_value(json!({
           "credential_issuer": "https://credential-issuer.example.com",
           "credentials": [
              "UniversityDegree_JWT",
              {
                 "format": "mso_mdoc",
                 "doctype": "org.iso.18013.5.1.mDL"
              }
           ],
           "grants": {
              "authorization_code": {
                 "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
              },
              "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                 "pre-authorized_code": "adhjhdjajkdkhjhdj",
                 "user_pin_required": true
              }
           }
        }))
        .unwrap();
    }
}
