use std::{path::PathBuf, process::ExitCode, sync::Arc};

use ::oid4vci::server::Oid4vciRouter;
use axum::routing::get;
use clap::Parser;
use open_auth2::server::{OAuth2ParRouter, OAuth2Router};
use ssi::JWK;
use tokio::fs;

mod config;
mod error;
mod oauth2;
mod oid4vci;

use config::Config;
use error::Error;
use oauth2::OAuth2State;

use crate::oid4vci::Oid4vciState;

/// OID4VCI server command line interface.
#[derive(Parser)]
struct Params {
    /// Listening port.
    #[arg(short, long)]
    port: Option<u32>,

    /// Enable the Push Authorization Request Endpoint.
    #[arg(short = 'u', long)]
    par: bool,

    /// Enabled Pre-Authorized Codes.
    #[arg(short = 'a', long)]
    pre_auth: bool,

    /// Enabled Credential Offers by reference.
    #[arg(short = 'r', long)]
    by_ref: bool,

    /// Sets the Transaction Code for Pre-Authorized grants.
    #[arg(short = 'c', long)]
    tx_code: Option<String>,

    /// Path to a JSON file containing the server configuration.
    ///
    /// If not set, the configuration will be read from the standard input.
    config_file: Option<PathBuf>,
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
    let mut config: Config = match &params.config_file {
        Some(path) => serde_json::from_str(&fs::read_to_string(path).await?)?,
        None => {
            eprintln!("Reading configuration from standard input...");
            serde_json::from_reader(std::io::stdin())?
        }
    };

    config.add_params(&params);

    let addr = format!("0.0.0.0:{}", config.port);

    let server = Arc::new(Server {
        config,
        jwk: JWK::generate_p256(),
        oid4vci: Oid4vciState::default(),
        oauth2: OAuth2State::default(),
    });

    // Setup routes.
    let router = axum::Router::new()
        .route("/health", get(health))
        .oauth2_routes()
        .oauth2_par_route()
        .oid4vci_routes()
        .route("/offer/new", get(oid4vci::new_credential_offer))
        .route(
            "/offer/{credential_offer_token}",
            get(oid4vci::credential_offer),
        )
        .with_state(server);

    // Start the server.
    println!("Listening on {addr}...");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await.map_err(Into::into)
}

struct Server {
    config: Config,

    jwk: JWK,

    oid4vci: Oid4vciState,

    oauth2: OAuth2State,
}

async fn health() {}
