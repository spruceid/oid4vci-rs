use std::{
    borrow::Cow,
    process::ExitCode,
    sync::{Arc, OnceLock},
};

use anyhow::{bail, Context};
use clap::Parser;
use http_body_util::Full;
use hyper::{
    body::Bytes, header::LOCATION, server::conn::http1, service::service_fn, Request, Response,
    StatusCode,
};
use hyper_util::rt::TokioIo;
use iref::UriBuf;
use oauth2::{reqwest, url::Url, ClientId, RedirectUrl};
use oid4vci::{
    authorization::{
        response::{AuthorizationResponse, AuthorizationResponseResult},
        Stateful,
    },
    client::{
        AuthorizationCodeRequired, CredentialToken, CredentialTokenState, Oid4vciClient,
        SimpleOid4vciClient, WaitingForTxCode,
    },
    proof::{jwt::create_jwt_proof, Proofs},
    response::CredentialResponse,
    CredentialOffer,
};
use ssi::{dids::DIDJWK, JWK};
use tokio::{select, sync::oneshot};

/// OID4VCI client command line interface.
#[derive(Parser)]
struct Params {
    /// Credential offer URL.
    offer_url: UriBuf,

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
    let credential_offer = CredentialOffer::from_uri(&params.offer_url)?;
    let http_client = reqwest::Client::new();

    let mut jwk = JWK::generate_p256();
    let did_url = DIDJWK::generate_url(&jwk);
    let did = did_url.did();
    jwk.key_id = Some(did_url.as_str().to_owned());

    let client = SimpleOid4vciClient::new(ClientId::new(did.as_str().to_owned()));

    let state = client
        .process_offer_async(&http_client, credential_offer)
        .await?;

    let credential_token = match state {
        CredentialTokenState::RequiresAuthorizationCode(state) => {
            require_authentication(&http_client, state, params.auto_auth).await?
        }
        CredentialTokenState::RequiresTxCode(state) => {
            require_tx_code(&http_client, state, params.tx_code.as_deref()).await?
        }
        CredentialTokenState::Ready(token) => token,
    };

    let credential_id = credential_token.default_credential_id()?;

    let nonce = credential_token.get_nonce_async(&http_client).await?;

    let proof = create_jwt_proof(
        Some(did.as_str().to_owned()),
        credential_token.credential_issuer().to_owned(),
        None,
        nonce,
        &jwk,
    )
    .await
    .unwrap();

    let proofs = Proofs::Jwt(vec![proof.into_string()]);

    let response = client
        .query_credential_async(&http_client, &credential_token, credential_id, Some(proofs))
        .await?;

    match response {
        CredentialResponse::Immediate(response) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&response.credentials).unwrap()
            );
            Ok(())
        }
        CredentialResponse::Deferred(_) => {
            todo!()
        }
    }
}

/// Run for Authorization Code grants.
///
/// If the `auto_auth` argument is set to `true`, the client will automatically
/// send a `GET` query to the redirect URL, expecting to be redirected
/// immediately.
async fn require_authentication<C: Oid4vciClient>(
    http_client: &reqwest::Client,
    authentication: AuthorizationCodeRequired<C>,
    auto_auth: bool,
) -> Result<CredentialToken<C::Profile>, anyhow::Error> {
    let port = 1234;
    let authority = format!("127.0.0.1:{port}");
    let listener = tokio::net::TcpListener::bind(&authority).await?;
    let redirect_url = RedirectUrl::new(format!("http://{authority}")).unwrap();
    let authentication = authentication
        .proceed_async(http_client, redirect_url)
        .await?;

    // Choose between auto auth, or manual auth.
    let (abort_sender, abort) = oneshot::channel();
    if auto_auth {
        let redirect_url = authentication.redirect_url().clone();
        tokio::spawn(async move {
            if let Err(e) = auto_authenticate(redirect_url).await {
                let _ = abort_sender.send(e);
            }
        });
    } else {
        eprintln!("Credential Offer requires an authentication through the following link:");
        eprintln!();
        eprintln!("  {}", authentication.redirect_url());
        eprintln!();
    }

    eprintln!("Waiting on authentication...");

    let (stream, _) = listener.accept().await?;
    let io = TokioIo::new(stream);
    let authorization_code = Arc::new(OnceLock::new());
    let connection = http1::Builder::new().keep_alive(false).serve_connection(
        io,
        service_fn(|request: Request<hyper::body::Incoming>| {
            let authorization_code = authorization_code.clone();
            let client_state = authentication.state().secret().clone();
            async move {
                let response =
                    match serde_urlencoded::from_str(request.uri().query().unwrap_or_default()) {
                        Ok(Stateful {
                            state: Some(state),
                            value: AuthorizationResponseResult::Ok(AuthorizationResponse { code }),
                        }) if state == client_state => {
                            let _ = authorization_code.set(code);
                            html_ok()
                        }
                        Ok(Stateful {
                            value: AuthorizationResponseResult::Err(response),
                            state: Some(state),
                        }) if state == client_state => {
                            html_err(response.error_description().map(String::as_str))
                        }
                        _ => html_err(None),
                    };

                Result::<_, anyhow::Error>::Ok(Response::new(Full::new(Bytes::from(response))))
            }
        }),
    );

    select! {
        result = connection => {
            result?;
        },
        error = abort => {
            if let Ok(e) = error {
                return Err(e);
            }
        }
    }

    let authorization_code = authorization_code
        .get()
        .cloned()
        .context("authentication failed")?;

    eprintln!("Authenticated!");

    authentication
        .proceed_async(http_client, authorization_code)
        .await
        .map_err(Into::into)
}

async fn auto_authenticate(url: Url) -> Result<(), anyhow::Error> {
    let client = reqwest::Client::new();

    eprintln!("Sending authentication query...");
    let response = client.get(url).send().await?;

    if response.status() != StatusCode::FOUND {
        bail!("expected redirection")
    }

    let Some(location) = response.headers().get(LOCATION) else {
        bail!("missing `Location` header")
    };

    let redirection_url = location.to_str()?;

    eprintln!("redirecting to `{redirection_url}`");
    let response = client.get(redirection_url).send().await?;

    if response.status() != StatusCode::OK {
        bail!("redirection failed")
    }

    Ok(())
}

fn html_ok() -> String {
    "<html><body><h1>Success!</h1><p>You can go back to the client now.</p></body></html>"
        .to_owned()
}

fn html_err(message: Option<&str>) -> String {
    format!(
        "<html><body><h1>Error</h1><p>{}</p></body></html>",
        message.unwrap_or("Unknown error")
    )
}

// Run for Pre-Authorized Code grants, with required Transaction Code.
//
// If the `tx_code` is set to `None`, the user will be prompted to manually
// enter a code.
async fn require_tx_code(
    http_client: &reqwest::Client,
    state: WaitingForTxCode,
    tx_code: Option<&str>,
) -> Result<CredentialToken, anyhow::Error> {
    eprintln!("Credential Offer requires an Transaction Code.");

    if let Some(description) = &state.tx_code_definition().description {
        eprintln!("{description}")
    }

    let tx_code = match tx_code {
        Some(tx_code) => {
            eprintln!("Using code: {tx_code}");
            Cow::Borrowed(tx_code)
        }
        None => {
            eprintln!();
            eprint!("Input code and press [Enter]: ");

            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            Cow::Owned(input.trim().to_owned())
        }
    };

    state
        .proceed_async(http_client, &tx_code)
        .await
        .map_err(Into::into)
}
