use std::borrow::Borrow;

use iref::UriBuf;
use open_auth2::server::AuthorizationServerMetadata;
use serde::{Deserialize, Serialize};

use crate::authorization::oauth2::{
    client_attestation::ClientAttestationServerParams, dpop::DpopServerParams,
};

pub type Oid4vciAuthorizationServerMetadata =
    AuthorizationServerMetadata<Oid4VciAuthorizationServerParams>;

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct Oid4VciAuthorizationServerParams {
    #[serde(default, rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,

    pub pushed_authorization_request_endpoint: Option<UriBuf>,

    #[serde(default)]
    pub require_pushed_authorization_requests: bool,

    #[serde(flatten)]
    pub dpop: DpopServerParams,

    #[serde(flatten)]
    pub client_attestation: ClientAttestationServerParams,
}

impl Borrow<ClientAttestationServerParams> for Oid4VciAuthorizationServerParams {
    fn borrow(&self) -> &ClientAttestationServerParams {
        &self.client_attestation
    }
}
