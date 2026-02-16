use std::{
    borrow::Cow,
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, OnceLock},
    time::Duration,
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
use oid4vci::{
    authorization::oauth2::client_attestation::ClientAttestation,
    client::{
        AuthorizationCodeRequired, CredentialToken, CredentialTokenState, Oid4vciClient,
        SimpleOid4vciClient, TxCodeRequired,
    },
    endpoints::credential::CredentialResponse,
    proof::{jwt::create_jwt_proof, Proofs},
    CredentialOffer,
};
use open_auth2::{
    grant::authorization_code::AuthorizationCodeAuthorizationResponse,
    reqwest,
    server::{ErrorResponse, ServerResult},
    ClientIdBuf, Stateful,
};
use ssi::{
    claims::{
        jws::{JwsSigner, JwsSignerInfo},
        JwsPayload, SignatureError,
    },
    dids::DIDJWK,
    JWK,
};
use tokio::{fs, select, sync::oneshot};

/// OID4VCI client command line interface.
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

    let mut jwk = match &params.jwk {
        Some(path) => fs::read_to_string(path).await?.parse()?,
        None => JWK::generate_p256(),
    };

    jwk.key_id = None;
    let did_url = DIDJWK::generate_url(&jwk);
    let did = did_url.did();
    jwk.key_id = Some(did_url.as_str().to_owned());
    jwk.public_key_use = Some("sig".to_owned());
    let client_id = ClientIdBuf::new(did.as_str().to_owned()).unwrap();

    eprintln!("client id: {}", client_id.as_str());

    let client_attestation = match &params.attester_jwk {
        Some(path) => {
            let mut attester_jwk: JWK = fs::read_to_string(path).await?.parse()?;

            let mut did_jwk = attester_jwk.clone();
            did_jwk.key_id = None;
            did_jwk.x509_certificate_chain = None; // Just so the DID isn't too long.
            let attester_kid = DIDJWK::generate_url(&did_jwk);
            attester_jwk.key_id = Some(attester_kid.clone().into_string());
            let attester_id = attester_kid.did().as_str();

            eprintln!("attester id: {attester_id}");

            Some(
                ClientAttestation::new(
                    attester_id.to_owned(),
                    client_id.clone(),
                    Duration::from_hours(24),
                    jwk.to_public(),
                )
                .sign(&attester_jwk)
                .await?,
            )
        }
        None => None,
    };

    let client = SimpleOid4vciClient::new(client_id)
        .with_signer(jwk.clone())
        .with_public_jwk(jwk.to_public())
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
            require_authentication(&params, &http_client, state, params.auto_auth).await?
        }
        CredentialTokenState::RequiresTxCode(state) => {
            require_tx_code(&http_client, state, params.tx_code.as_deref()).await?
        }
        CredentialTokenState::Ready(token) => token,
    };

    let credential_id = credential_token.default_credential_id()?;

    let nonce = client.get_nonce(&credential_token, &http_client).await?;

    let proof = create_jwt_proof(
        Some(did.as_str().to_owned()),
        credential_token.credential_issuer().to_owned(),
        None,
        nonce,
        EmbedPublicJwk(&jwk),
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
    params: &Params,
    http_client: &reqwest::Client,
    authentication: AuthorizationCodeRequired<C>,
    auto_auth: bool,
) -> Result<CredentialToken<C::Profile>, anyhow::Error> {
    let authority = format!("127.0.0.1:{}", params.port);

    let redirect_url = match &params.url {
        Some(url) => UriBuf::new(url.as_str().to_owned().into_bytes()).unwrap(),
        None => UriBuf::new(format!("http://{authority}").into_bytes()).unwrap(),
    };

    let listener = tokio::net::TcpListener::bind(&authority).await?;
    let authentication = authentication.proceed(http_client, redirect_url).await?;

    // Choose between auto auth, or manual auth.
    let (abort_sender, abort) = oneshot::channel();
    if auto_auth {
        let redirect_url = authentication.redirect_url().to_owned();
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
            let client_state = authentication.state().to_owned();
            async move {
                let response = match serde_urlencoded::from_str(
                    request.uri().query().unwrap_or_default(),
                ) {
                    Ok(Stateful {
                        state: Some(state),
                        value: ServerResult::Ok(AuthorizationCodeAuthorizationResponse { code }),
                    }) if state == client_state => {
                        let _ = authorization_code.set(code);
                        html_ok()
                    }
                    Ok(Stateful {
                        value: ServerResult::Err(response),
                        state: Some(state),
                    }) if state == client_state => html_err(Some(response)),
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
        .proceed(http_client, authorization_code)
        .await
        .map_err(Into::into)
}

async fn auto_authenticate(url: UriBuf) -> Result<(), anyhow::Error> {
    let client = reqwest::Client::new();

    eprintln!("Sending authentication query at `{url}`...");
    let response = client.get(url.as_str()).send().await?;

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

fn html_err(response: Option<ErrorResponse>) -> String {
    let description = response
        .as_ref()
        .and_then(|r| r.error_description.as_deref());
    format!(
        "<html><body><h1>Error</h1><p>{}</p></body></html>",
        description.unwrap_or("Unknown error")
    )
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

pub struct EmbedPublicJwk<'a>(&'a JWK);

impl<'a> JwsSigner for EmbedPublicJwk<'a> {
    async fn fetch_info(&self) -> Result<JwsSignerInfo, SignatureError> {
        let mut info = self.0.fetch_info().await?;
        info.jwk = Some(self.0.to_public());
        Ok(info)
    }

    async fn sign_bytes(&self, signing_bytes: &[u8]) -> Result<Vec<u8>, SignatureError> {
        self.0.sign_bytes(signing_bytes).await
    }
}
