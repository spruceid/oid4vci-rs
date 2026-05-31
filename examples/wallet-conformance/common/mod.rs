//! Shared helpers for the wallet conformance examples.
//!
//! Both `wallet-oid4vci-conformance` and `wallet-fapi2-conformance` act as the
//! same HAIP wallet: a `did:jwk` client identifier, an optional Client
//! Attestation, DPoP-bound requests and a loopback redirect listener to capture
//! the Authorization Response. This module factors out that common setup.
//!
//! The module is shared by `#[path]` inclusion, so each example compiles it in
//! full; `dead_code` is allowed because not every helper is used by both.
#![allow(dead_code)]

use std::{
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{bail, Context};
use http_body_util::Full;
use hyper::{
    body::Bytes, header::LOCATION, server::conn::http1, service::service_fn, Request, Response,
    StatusCode,
};
use hyper_util::rt::TokioIo;
use iref::{Uri, UriBuf};
use oid4vci::authorization::oauth2::client_attestation::ClientAttestation;
use open_auth2::{
    grant::authorization_code::AuthorizationCodeAuthorizationResponse,
    reqwest,
    server::{ErrorResponse, ServerResult},
    ClientIdBuf, CodeBuf, State, Stateful,
};
use ssi::{
    claims::{JwsBuf, JwsPayload},
    dids::DIDJWK,
    JWK,
};
use tokio::{fs, net::TcpListener, select, sync::oneshot};

/// The wallet's signing key and the identifiers derived from it.
pub struct WalletKey {
    /// Signing JWK (with `kid` set to the `did:jwk` URL).
    pub jwk: JWK,

    /// The `did:jwk` identifier, used as the proof `iss`/`kid`.
    pub did: String,

    /// Client identifier (the `did:jwk`), used in OAuth requests.
    pub client_id: ClientIdBuf,
}

/// Loads (or generates) the wallet signing key and derives its `did:jwk`
/// identifier.
pub async fn load_wallet_key(path: Option<&Path>) -> anyhow::Result<WalletKey> {
    let mut jwk: JWK = match path {
        Some(path) => fs::read_to_string(path).await?.parse()?,
        None => JWK::generate_p256(),
    };

    jwk.key_id = None;
    let did_url = DIDJWK::generate_url(&jwk);
    let did = did_url.did().as_str().to_owned();
    jwk.key_id = Some(did_url.as_str().to_owned());
    jwk.public_key_use = Some("sig".to_owned());
    let client_id = ClientIdBuf::new(did.clone()).unwrap();

    eprintln!("client id: {}", client_id.as_str());

    Ok(WalletKey {
        jwk,
        did,
        client_id,
    })
}

/// Builds and signs a Client Attestation JWT for the wallet key, if an attester
/// JWK path is provided. Returns `None` when client attestation is disabled.
pub async fn load_client_attestation(
    attester_path: Option<&Path>,
    wallet: &WalletKey,
) -> anyhow::Result<Option<JwsBuf>> {
    let Some(path) = attester_path else {
        return Ok(None);
    };

    let mut attester_jwk: JWK = fs::read_to_string(path).await?.parse()?;

    let mut did_jwk = attester_jwk.clone();
    did_jwk.key_id = None;
    did_jwk.x509_certificate_chain = None; // Just so the DID isn't too long.
    let attester_kid = DIDJWK::generate_url(&did_jwk);
    attester_jwk.key_id = Some(attester_kid.clone().into_string());
    let attester_id = attester_kid.did().as_str();

    eprintln!("attester id: {attester_id}");

    Ok(Some(
        ClientAttestation::new(
            attester_id.to_owned(),
            wallet.client_id.clone(),
            Duration::from_hours(24),
            wallet.jwk.to_public(),
        )
        .sign(&attester_jwk)
        .await?,
    ))
}

/// Resolves the wallet's loopback redirect URL from the `--port`/`--url`
/// options, and binds a listener on it.
///
/// Returns the redirect URL to advertise to the Authorization Server together
/// with the bound listener.
pub async fn bind_redirect_listener(
    port: u32,
    url: Option<&Uri>,
) -> anyhow::Result<(UriBuf, TcpListener)> {
    let authority = format!("127.0.0.1:{port}");

    let redirect_url = match url {
        Some(url) => UriBuf::new(url.as_str().to_owned().into_bytes()).unwrap(),
        None => UriBuf::new(format!("http://{authority}").into_bytes()).unwrap(),
    };

    let listener = TcpListener::bind(&authority).await?;

    Ok((redirect_url, listener))
}

/// Query parameters validated on the Authorization Response in addition to the
/// authorization code.
#[derive(serde::Deserialize)]
struct ResponseGuards {
    /// `iss` Authorization Response parameter (RFC 9207).
    iss: Option<String>,
}

/// Waits for the Authorization Response on the loopback listener and returns the
/// Authorization Code.
///
/// The `state` returned in the response is validated against `expected_state`
/// (FAPI2 / RFC 6749), and the `redirect_url` is the Authorization Request URL
/// the user agent must visit. When `auto` is set, the URL is fetched
/// automatically, expecting an immediate redirect.
///
/// When `expected_iss` is `Some`, the `iss` Authorization Response parameter is
/// required and validated against it, as mandated by [RFC 9207] (the FAPI2
/// Security Profile, required by HAIP, relies on this to defend against mix-up
/// attacks). A missing or mismatched `iss` is rejected.
///
/// [RFC 9207]: https://www.rfc-editor.org/rfc/rfc9207
pub async fn obtain_authorization_code(
    listener: TcpListener,
    redirect_url: &Uri,
    expected_state: &State,
    expected_iss: Option<&Uri>,
    auto: bool,
) -> anyhow::Result<CodeBuf> {
    let (abort_sender, abort) = oneshot::channel();
    if auto {
        let redirect_url = redirect_url.to_owned();
        tokio::spawn(async move {
            if let Err(e) = auto_authenticate(redirect_url).await {
                let _ = abort_sender.send(e);
            }
        });
    } else {
        eprintln!("Authentication is required through the following link:");
        eprintln!();
        eprintln!("  {redirect_url}");
        eprintln!();
    }

    eprintln!("Waiting on authentication...");

    let (stream, _) = listener.accept().await?;
    let io = TokioIo::new(stream);
    let authorization_code = Arc::new(OnceLock::new());
    let expected_state = expected_state.to_owned();
    let expected_iss = expected_iss.map(|iss| iss.as_str().to_owned());
    let connection = http1::Builder::new().keep_alive(false).serve_connection(
        io,
        service_fn(|request: Request<hyper::body::Incoming>| {
            let authorization_code = authorization_code.clone();
            let expected_state = expected_state.clone();
            let expected_iss = expected_iss.clone();
            async move {
                let query = request.uri().query().unwrap_or_default();

                // RFC 9207: when an issuer identifier is expected, the `iss`
                // Authorization Response parameter MUST be present and match.
                let iss_ok = match &expected_iss {
                    Some(expected) => matches!(
                        serde_urlencoded::from_str::<ResponseGuards>(query),
                        Ok(ResponseGuards { iss: Some(iss) }) if &iss == expected
                    ),
                    None => true,
                };

                let response = match serde_urlencoded::from_str(query) {
                    Ok(Stateful {
                        state: Some(state),
                        value: ServerResult::Ok(AuthorizationCodeAuthorizationResponse { code }),
                    }) if iss_ok && state == expected_state => {
                        let _ = authorization_code.set(code);
                        html_ok()
                    }
                    Ok(Stateful {
                        value: ServerResult::Err(response),
                        state: Some(state),
                    }) if state == expected_state => html_err(Some(response)),
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

    authorization_code
        .get()
        .cloned()
        .context("authentication failed")
}

async fn auto_authenticate(url: UriBuf) -> anyhow::Result<()> {
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
