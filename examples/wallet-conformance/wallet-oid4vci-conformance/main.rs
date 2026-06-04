//! OID4VCI 1.0 wallet conformance client.
//!
//! Drives the credential issuance flow (Pre-Authorized Code or Authorization
//! Code with PAR) against the OpenID Foundation conformance suite acting as the
//! Credential Issuer, then requests the credential (immediate or deferred).
//!
//! See `examples/wallet-conformance/README.md` for the full setup and the list of
//! conformance modules this example covers.

use std::{borrow::Cow, path::PathBuf, process::ExitCode, time::Duration};

use anyhow::Context;
use clap::Parser;
use iref::UriBuf;
use oid4vci::{
    client::{
        AuthorizationCodeRequired, CredentialToken, CredentialTokenState, Oid4vciClient,
        SimpleOid4vciClient, TxCodeRequired,
    },
    endpoints::credential::CredentialResponse,
    proof::{
        jwt::{create_jwt_proof, JwkProofSigner},
        Proofs,
    },
    CredentialOffer,
};
use open_auth2::reqwest;

#[path = "../common/mod.rs"]
mod common;

use common::WalletKey;

/// OID4VCI wallet conformance client.
#[derive(Parser)]
struct Params {
    /// Credential offer URL.
    offer_url: Option<UriBuf>,

    /// Sets the expected Transaction Code for Pre-Authorized grants.
    ///
    /// If not set, the user will be prompted to enter one manually if required.
    #[arg(short = 'c', long)]
    tx_code: Option<String>,

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

    let offer_url = match &params.offer_url {
        Some(offer_url) => Cow::Borrowed(offer_url.as_uri()),
        None => {
            let mut offer_url = String::new();
            println!("Enter the credential offer URL:");
            std::io::stdin().read_line(&mut offer_url).unwrap();
            Cow::Owned(
                UriBuf::new(offer_url.trim().to_owned().into_bytes())
                    .ok()
                    .context("invalid offer URL")?,
            )
        }
    };

    let credential_offer = CredentialOffer::from_uri(&offer_url)?;

    let offer = client.resolve_offer(&http_client, credential_offer).await?;

    let state = client.accept_offer(&http_client, offer).await?;

    let credential_token = match state {
        CredentialTokenState::RequiresAuthorizationCode(state) => {
            require_authentication(&params, &http_client, &wallet, state, params.auto_auth).await?
        }
        CredentialTokenState::RequiresTxCode(state) => {
            require_tx_code(&http_client, state, params.tx_code.as_deref()).await?
        }
        CredentialTokenState::Ready(token) => token,
    };

    let credential_id = credential_token.default_credential_id()?;

    let nonce = client.get_nonce(&credential_token, &http_client).await?;

    let proof = create_jwt_proof(
        Some(wallet.did.clone()),
        credential_token.credential_issuer().to_owned(),
        None,
        nonce,
        JwkProofSigner(&wallet.jwk),
    )
    .await
    .unwrap();

    let proofs = Proofs::Jwt(vec![proof]);

    let response = client
        .exchange_credential(&http_client, &credential_token, credential_id, Some(proofs))
        .await?;

    match response {
        CredentialResponse::Immediate(response) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&response.credentials).unwrap()
            );
            Ok(())
        }
        CredentialResponse::Deferred(mut deferred) => loop {
            eprintln!(
                "Credential issuance deferred; retrying in {}s (transaction {})...",
                deferred.interval, deferred.transaction_id
            );
            tokio::time::sleep(Duration::from_secs(deferred.interval)).await;

            match client
                .exchange_deferred_credential(
                    &http_client,
                    &credential_token,
                    deferred.transaction_id.clone(),
                )
                .await?
            {
                CredentialResponse::Immediate(response) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&response.credentials).unwrap()
                    );
                    break Ok(());
                }
                CredentialResponse::Deferred(next) => deferred = next,
            }
        },
    }
}

/// Run for Authorization Code grants.
///
/// If the `auto_auth` argument is set to `true`, the client will automatically
/// send a `GET` query to the redirect URL, expecting to be redirected
/// immediately.
async fn require_authentication<C: Oid4vciClient>(
    params: &Params,
    http_client: &reqwest::Client,
    _wallet: &WalletKey,
    authentication: AuthorizationCodeRequired<C>,
    auto_auth: bool,
) -> Result<CredentialToken<C::Profile>, anyhow::Error> {
    let (redirect_url, listener) =
        common::bind_redirect_listener(params.port, params.url.as_deref()).await?;

    let authentication = authentication.proceed(http_client, redirect_url).await?;

    let authorization_code = common::obtain_authorization_code(
        listener,
        authentication.redirect_url(),
        authentication.state(),
        None,
        auto_auth,
    )
    .await?;

    eprintln!("Authenticated!");

    authentication
        .proceed(http_client, authorization_code)
        .await
        .map_err(Into::into)
}

// Run for Pre-Authorized Code grants, with required Transaction Code.
//
// If the `tx_code` is set to `None`, the user will be prompted to manually
// enter a code.
async fn require_tx_code<C: Oid4vciClient>(
    http_client: &reqwest::Client,
    state: TxCodeRequired<C>,
    tx_code: Option<&str>,
) -> Result<CredentialToken<C::Profile>, anyhow::Error> {
    eprintln!("Credential Offer requires an Transaction Code.");

    if let Some(description) = &state.tx_code_definition().description {
        eprintln!("{description}")
    }

    let tx_code = match tx_code {
        Some(tx_code) => {
            eprintln!("Using code: {tx_code}");
            tx_code.to_owned()
        }
        None => {
            eprintln!();
            eprint!("Input code and press [Enter]: ");

            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            input.trim().to_owned()
        }
    };

    state
        .proceed(http_client, tx_code)
        .await
        .map_err(Into::into)
}
