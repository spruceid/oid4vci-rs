//! OID4VCI 1.0 issuer conformance server.
//!
//! An OID4VCI Credential Issuer + OAuth2 Authorization Server (with PAR) driven
//! by the OpenID Foundation conformance suite acting as the wallet. Covers the
//! `oid4vci-1_0-issuer-*` and `fapi2-security-profile-final-*` test plans.
//!
//! The suite (running in the cloud) must reach this server, so expose it with a
//! tunnel (e.g. ngrok) and pass the public URL via `--public-url`; that URL is
//! used as the Credential Issuer identifier and in all advertised endpoints.
//!
//! See `examples/issuer-conformance/README.md` for the full setup.

use std::{path::PathBuf, process::ExitCode, sync::Arc};

use ::oid4vci::server::Oid4vciRouter;
use axum::routing::{get, post};
use clap::Parser;
use iref::UriBuf;
use open_auth2::{reqwest, server::OAuth2Router};
use ssi::JWK;
use tokio::{
    fs,
    io::{AsyncBufReadExt, BufReader},
};

mod config;
mod error;
mod oauth2;
mod oid4vci;

use config::Config;
use error::Error;
use oauth2::OAuth2State;

use crate::oid4vci::Oid4vciState;

/// OID4VCI issuer conformance server.
#[derive(Parser)]
struct Params {
    /// Public URL where the suite can reach this issuer (e.g. the ngrok URL).
    ///
    /// Used as the Credential Issuer identifier and to build every advertised
    /// endpoint. Must match `vci.credential_issuer_url` in `test.json`.
    #[arg(short = 'P', long)]
    public_url: UriBuf,

    /// Listening port.
    #[arg(short, long, default_value = "3000")]
    port: u32,

    /// Path to the issuer's Credential signing JWK.
    ///
    /// Must carry an `x5c` chain to the Credential Trust Anchor configured in
    /// the suite (the generated `crypto/issuer/jwk.json` already does).
    #[arg(
        short = 'k',
        long,
        default_value = "examples/issuer-conformance/crypto/issuer/jwk.json"
    )]
    issuer_jwk: PathBuf,

    /// Path to the trusted Client Attester's public JWK.
    ///
    /// Used to verify the signature on the Client Attestation JWT presented for
    /// Attestation-Based Client Authentication (the generated
    /// `crypto/attester/jwk.pub.json`, whose private half the suite signs with).
    #[arg(
        short = 'a',
        long,
        default_value = "examples/issuer-conformance/crypto/attester/jwk.pub.json"
    )]
    attester_jwk: PathBuf,

    /// Registered client redirect URI(s).
    ///
    /// The redirect URIs the client (the suite-wallet) is registered with — i.e.
    /// the suite's callback, e.g.
    /// `https://www.certification.openid.net/test/a/<alias>/callback`. When set,
    /// the PAR endpoint rejects an authorization request whose `redirect_uri` is
    /// not one of these (FAPI2 §5.3.1.1 / RFC 6749 §3.1.2.3) instead of
    /// redirecting to it. May be repeated. When omitted, any `redirect_uri` is
    /// accepted.
    #[arg(short = 'r', long = "redirect-uri")]
    redirect_uris: Vec<UriBuf>,

    /// Require an interactive approve/deny consent step at the Authorization
    /// Endpoint instead of auto-approving.
    ///
    /// Enable this to run the FAPI2 tests that need the user to deny consent
    /// (`user-rejects-authentication`) or to reuse a `request_uri` before
    /// authentication completes. Leave it off (the default) for the headless,
    /// auto-approving flow every other test expects.
    #[arg(long)]
    manual_consent: bool,
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
    let jwk: JWK = fs::read_to_string(&params.issuer_jwk).await?.parse()?;
    let attester_jwk: JWK = fs::read_to_string(&params.attester_jwk).await?.parse()?;

    let mut config = Config::new(params.public_url.clone(), params.port, params.redirect_uris);
    config.manual_consent = params.manual_consent;

    let addr = format!("0.0.0.0:{}", config.port);

    // Values needed to build issuer-initiated Credential Offers.
    let issuer_url = params.public_url.clone();
    let credential_configuration_ids: Vec<String> =
        config.credential_configurations.keys().cloned().collect();

    let server = Arc::new(Server {
        config,
        jwk,
        attester_jwk,
        oid4vci: Oid4vciState::default(),
        oauth2: OAuth2State::default(),
    });

    // Setup routes.
    //
    // The PAR endpoint is wired with a custom handler (rather than open_auth2's
    // `oauth2_par_route`) so it can read the `OAuth-Client-Attestation`(-PoP)
    // HTTP headers and authenticate the client (ATCA draft-07 §6) before
    // processing the pushed request.
    let router = axum::Router::new()
        .route("/health", get(health))
        .oauth2_routes()
        .route("/par", post(oauth2::par))
        .route("/authorize/decision", get(oauth2::authorize_decision))
        .oid4vci_routes()
        .route("/offer/new", get(oid4vci::new_credential_offer))
        .route(
            "/offer/{credential_offer_token}",
            get(oid4vci::credential_offer),
        )
        .with_state(server);

    // Start the server. It supports every flow out of the box: wallet-initiated
    // and Pre-Authorized Code flows are driven entirely through the HTTP
    // endpoints, while issuer-initiated flows are driven through the interactive
    // prompt below — all without restarting the process.
    println!("Listening on {addr} (public URL: {})...", params.public_url);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let server_task = tokio::spawn(async move { axum::serve(listener, router).await });

    drive_issuer_initiated_offers(&issuer_url, &credential_configuration_ids).await?;

    server_task.await?.map_err(Into::into)
}

/// Prompts for wallet `credential_offer_endpoint`s on stdin and delivers a
/// Credential Offer (by value) to each, as needed by the issuer-initiated flow
/// (OID4VCI §4.1). Always available while the server runs; other flows simply
/// ignore it. When stdin is closed (non-interactive), it returns immediately and
/// the server keeps serving.
async fn drive_issuer_initiated_offers(
    issuer_url: &UriBuf,
    credential_configuration_ids: &[String],
) -> Result<(), anyhow::Error> {
    let http_client = reqwest::Client::new();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();

    eprintln!();
    eprintln!("Ready. For the issuer-initiated flow, paste the wallet's");
    eprintln!("`credential_offer_endpoint` (exported by the conformance test) to");
    eprintln!("deliver a Credential Offer. Other flows need nothing here. Ctrl+C to quit.");
    eprintln!();
    eprint!("credential_offer_endpoint> ");

    while let Some(line) = lines.next_line().await? {
        let endpoint = line.trim();
        if !endpoint.is_empty() {
            let offer = serde_json::json!({
                "credential_issuer": issuer_url.as_str(),
                "credential_configuration_ids": credential_configuration_ids,
                "grants": { "authorization_code": {} }
            });

            // Deliver the offer by value: `{endpoint}?credential_offer=<JSON>`.
            let query = serde_urlencoded::to_string([(
                "credential_offer",
                serde_json::to_string(&offer)?,
            )])?;
            let url = format!("{endpoint}?{query}");

            match http_client.get(&url).send().await {
                Ok(response) => {
                    eprintln!(
                        "Delivered Credential Offer to {endpoint} (HTTP {}).",
                        response.status()
                    )
                }
                Err(e) => eprintln!("Failed to deliver Credential Offer: {e}"),
            }
        }
        eprint!("credential_offer_endpoint> ");
    }

    Ok(())
}

struct Server {
    config: Config,

    jwk: JWK,

    /// Trusted Client Attester public key, used to verify Client Attestation
    /// JWTs (Attestation-Based Client Authentication).
    attester_jwk: JWK,

    oid4vci: Oid4vciState,

    oauth2: OAuth2State,
}

async fn health() {}
