//! FAPI2 wallet conformance client.
//!
//! Drives the bare OAuth2 / FAPI2 Security Profile flow that the OpenID
//! Foundation `fapi2-security-profile-final-client-test-*` modules expect (the
//! HAIP profile requires FAPI2 compliance, see HAIP §4):
//!
//! 1. discover the Authorization Server metadata from the issuer (RFC 8414);
//! 2. push an Authorization Request (PAR) with PKCE `S256`, Client Attestation
//!    and DPoP, then visit the Authorization Endpoint (immediate redirect);
//! 3. validate the Authorization Response `state` (RFC 6749) and `iss`
//!    (RFC 9207) before exchanging the code at the Token Endpoint;
//! 4. make a DPoP-bound GET to the protected resource endpoint.
//!
//! Unlike `wallet-oid4vci-conformance`, there is no Credential Offer: the flow
//! is started from the issuer/discovery URL and ends at the resource endpoint.
//!
//! See `examples/wallet-conformance/README.md` for the shared setup.

use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use iref::{Uri, UriBuf};
use oid4vci::authorization::{
    oauth2::{client_attestation::AddClientAttestation, dpop::AddDpop},
    server::Oid4vciAuthorizationServerMetadata,
};
use oid4vci::client::SimpleOid4vciClient;
use open_auth2::{
    client::{OAuth2Client, OAuth2ClientError},
    endpoints::{
        authorization::AuthorizationEndpoint, pushed_authorization::PushedAuthorizationEndpoint,
        token::TokenEndpoint, Endpoint, HttpRequest, RequestBuilder,
    },
    ext::pkce::{AddPkceChallenge, AddPkceVerifier, PkceCodeChallengeAndMethod},
    grant::authorization_code::ExchangeCode,
    http, reqwest,
    transport::{expect_content_type, HttpClient, NoContent, APPLICATION_JSON},
    util::Discoverable,
    AddAccessToken, AddState, ScopeBuf, StateBuf,
};

#[path = "../common/mod.rs"]
mod common;

/// FAPI2 wallet conformance client.
#[derive(Parser)]
struct Params {
    /// Authorization Server / Credential Issuer identifier.
    ///
    /// The AS metadata is discovered from this URL (RFC 8414); its `issuer`
    /// MUST match.
    #[arg(short, long)]
    issuer: UriBuf,

    /// Protected resource endpoint to GET after authorization (e.g. the
    /// `accounts` or `userinfo` endpoint exported by the test).
    ///
    /// Optional: negative tests (e.g. `discovery-issuer-mismatch`, invalid
    /// `iss`/`state`) abort before the resource request, so the flow can stop
    /// right after the token exchange when this is omitted.
    #[arg(short, long)]
    resource_url: Option<UriBuf>,

    /// Requested scope.
    ///
    /// Optional and sent only when provided. Note that the `plain_oauth` FAPI2
    /// client type rejects the `openid` scope (that scope implies OpenID
    /// Connect).
    #[arg(short, long)]
    scope: Option<String>,

    /// Enable auto authorization.
    ///
    /// If set, the Authorization Endpoint will be queried automatically,
    /// expecting an immediate redirect.
    #[arg(short = 'a', long)]
    auto_auth: bool,

    /// Path to a file containing the client's JWK.
    ///
    /// If unset, a random JWK will be generated.
    #[arg(short = 'k', long)]
    jwk: Option<PathBuf>,

    /// Path to a file containing the client attester's JWK.
    ///
    /// If unset, client attestation is disabled.
    #[arg(short = 't', long)]
    attester_jwk: Option<PathBuf>,

    /// Port (for authorization).
    #[arg(short, long, default_value = "1234")]
    port: u32,

    /// Base URL of the client (for authorization).
    ///
    /// Defaults to `http://127.0.0.1:{PORT}/`
    #[arg(short, long)]
    url: Option<UriBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::init();
    let params = Params::parse();

    match run(params).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(params: Params) -> Result<(), anyhow::Error> {
    let http_client = reqwest::Client::new();

    let wallet = common::load_wallet_key(params.jwk.as_deref()).await?;
    let client_attestation =
        common::load_client_attestation(params.attester_jwk.as_deref(), &wallet).await?;

    let client = SimpleOid4vciClient::new(wallet.client_id.clone())
        .with_signer(wallet.jwk.clone())
        .with_public_jwk(wallet.jwk.to_public())
        .with_client_attestation_opt(client_attestation);

    // 1. Discover the Authorization Server metadata. `discover` validates that
    //    the advertised `issuer` matches the requested one (RFC 8414).
    let as_metadata =
        Oid4vciAuthorizationServerMetadata::discover(&http_client, &params.issuer).await?;

    let scope = params
        .scope
        .as_deref()
        .and_then(|scope| ScopeBuf::new(scope.to_owned()).ok());

    // 2. Authorization Request (via PAR when required) with PKCE, Client
    //    Attestation and DPoP.
    let (redirect_url, listener) =
        common::bind_redirect_listener(params.port, params.url.as_deref()).await?;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallengeAndMethod::new_random_sha256();
    let state = StateBuf::new_random();

    let authorization_endpoint = AuthorizationEndpoint::new(
        &client,
        as_metadata
            .authorization_endpoint
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing authorization endpoint"))?,
    );

    let server_redirect_url = match &as_metadata.extra.pushed_authorization_request_endpoint {
        Some(par_endpoint_url) => {
            let par_endpoint = PushedAuthorizationEndpoint::new(&client, par_endpoint_url);

            par_endpoint
                .authorize_url(Some(redirect_url.clone()), scope.clone())
                .with_state(Some(state.clone()))
                .with_pkce_challenge(pkce_challenge)
                .with_client_attestation(&as_metadata)
                .with_dpop(None, None)
                .send(&http_client)
                .await?
                .for_endpoint(&authorization_endpoint)
        }
        None => authorization_endpoint
            .authorize_url(Some(redirect_url.clone()), scope.clone())
            .with_state(Some(state.clone()))
            .with_pkce_challenge(pkce_challenge)
            .with_client_attestation(&as_metadata)
            .with_dpop(None, None)
            .into_redirect_uri(),
    };

    // 3. Wait for the Authorization Response, validating `state` and `iss`.
    let authorization_code = common::obtain_authorization_code(
        listener,
        &server_redirect_url,
        &state,
        Some(&as_metadata.issuer),
        params.auto_auth,
    )
    .await?;

    eprintln!("Authenticated!");

    // 4. Exchange the authorization code for an access token.
    let token_endpoint = TokenEndpoint::new(
        &client,
        as_metadata
            .token_endpoint
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing token endpoint"))?,
    );

    let token = token_endpoint
        .exchange_code(authorization_code, Some(redirect_url))
        .with_pkce_verifier(&pkce_verifier)
        .with_client_attestation(&as_metadata)
        .with_dpop(None, None)
        .send(&http_client)
        .await?;

    eprintln!("Access token obtained ({}).", token.token_type);

    // 5. DPoP-bound request to the protected resource endpoint, when one is
    //    provided. Negative modules abort before this step.
    let Some(resource_url) = &params.resource_url else {
        eprintln!("No --resource-url provided; stopping after the token exchange.");
        return Ok(());
    };

    let resource = RequestBuilder::new(
        ResourceEndpoint::new(&client, resource_url),
        ResourceRequest,
    )
    .with_access_token(&token.token_type, &token.access_token)
    .with_dpop(Some(&token.access_token), None)
    .send(&http_client)
    .await?;

    println!("{}", serde_json::to_string_pretty(&resource).unwrap());

    Ok(())
}

/// A protected resource endpoint accessed with a (DPoP-bound) access token.
struct ResourceEndpoint<'a, C> {
    client: &'a C,
    uri: &'a Uri,
}

impl<'a, C> ResourceEndpoint<'a, C> {
    fn new(client: &'a C, uri: &'a Uri) -> Self {
        Self { client, uri }
    }
}

impl<'a, C> Endpoint for ResourceEndpoint<'a, C>
where
    C: OAuth2Client,
{
    type Client = C;

    fn client(&self) -> &Self::Client {
        self.client
    }

    fn uri(&self) -> &Uri {
        self.uri
    }
}

/// A GET request to a protected resource endpoint, returning its JSON body.
struct ResourceRequest;

impl<'a, C> HttpRequest<ResourceEndpoint<'a, C>> for ResourceRequest
where
    C: OAuth2Client,
{
    type ContentType = NoContent;
    type RequestBody<'b>
        = ()
    where
        Self: 'b;
    type Response = serde_json::Value;
    type ResponsePayload = serde_json::Value;

    async fn build_request(
        &self,
        endpoint: &ResourceEndpoint<'a, C>,
        _http_client: &impl HttpClient,
    ) -> Result<http::Request<Self::RequestBody<'_>>, OAuth2ClientError> {
        Ok(http::Request::builder()
            .method(http::Method::GET)
            .uri(endpoint.uri.as_str())
            .header(http::header::ACCEPT, &APPLICATION_JSON)
            .body(())
            .unwrap())
    }

    fn decode_response(
        &self,
        _endpoint: &ResourceEndpoint<'a, C>,
        response: http::Response<Vec<u8>>,
    ) -> Result<http::Response<Self::ResponsePayload>, OAuth2ClientError> {
        let status = response.status();
        if status != http::StatusCode::OK {
            return Err(OAuth2ClientError::ServerError(status));
        }

        expect_content_type(response.headers(), &APPLICATION_JSON)?;
        let body = serde_json::from_slice(response.body()).map_err(OAuth2ClientError::response)?;
        Ok(response.map(|_| body))
    }

    async fn process_response(
        &self,
        _endpoint: &ResourceEndpoint<'a, C>,
        _http_client: &impl HttpClient,
        response: http::Response<Self::ResponsePayload>,
    ) -> Result<Self::Response, OAuth2ClientError> {
        Ok(response.into_body())
    }
}
