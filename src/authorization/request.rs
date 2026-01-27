use oauth2::{ClientId, PkceCodeChallenge, RedirectUrl, Scope};
use serde::Deserialize;

use crate::authorization::authorization_details::{
    AnyCredentialAuthorizationParams, CredentialAuthorizationDetailsRequest,
    CredentialAuthorizationParams,
};

#[derive(Deserialize)]
pub struct AuthorizationRequestParams<P> {
    pub client_id: ClientId,

    #[serde(flatten)]
    pub pkce_challenge: Option<PkceCodeChallenge>,

    pub redirect_uri: Option<RedirectUrl>,

    pub response_type: String,

    #[serde(default)]
    pub scopes: Vec<Scope>,

    #[serde(flatten)]
    pub extra_params: P,
}

#[derive(Deserialize)]
#[serde(bound = "T: CredentialAuthorizationParams")]
pub struct CredentialAuthorizationRequestParams<
    T: CredentialAuthorizationParams = AnyCredentialAuthorizationParams,
> {
    #[serde(default)]
    pub authorization_details: Vec<CredentialAuthorizationDetailsRequest<T>>,
}

/// OID4VCI Authorization Request.
///
/// This is an extension to the [`oauth2::AuthorizationRequest`] type.
pub trait Oid4vciAuthorizationRequest<'a>: Sized {
    /// Sets the `authorization_details` parameter.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-authorization-details>
    fn set_authorization_details<T: CredentialAuthorizationParams>(
        self,
        authorization_details: Vec<CredentialAuthorizationDetailsRequest<T>>,
    ) -> Self;

    /// Sets the `issuer_state` parameter.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-additional-request-paramete>
    fn set_issuer_state(self, value: &'a str) -> Self;

    /// Sets the `issuer_state` parameter.
    ///
    /// See: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-additional-request-paramete>
    fn set_issuer_state_option(self, value: Option<&'a str>) -> Self {
        match value {
            Some(value) => self.set_issuer_state(value),
            None => self,
        }
    }
}

impl<'a> Oid4vciAuthorizationRequest<'a> for oauth2::AuthorizationRequest<'a> {
    fn set_authorization_details<T: CredentialAuthorizationParams>(
        self,
        authorization_details: Vec<CredentialAuthorizationDetailsRequest<T>>,
    ) -> Self {
        if authorization_details.is_empty() {
            self
        } else {
            self.add_extra_param(
                "authorization_details",
                serde_json::to_string(&authorization_details)
                    // UNWRAP: Authorization details are always serializable as
                    //         JSON.
                    .unwrap(),
            )
        }
    }

    fn set_issuer_state(self, value: &'a str) -> Self {
        self.add_extra_param("issuer_state", value)
    }
}
