# Issuer Conformance

An OID4VCI 1.0 **Credential Issuer** + OAuth2 Authorization Server (with PAR),
driven by the OpenID Foundation conformance suite acting as the **wallet** (the
mirror image of [`../wallet-conformance/`](../wallet-conformance/), where the
suite is the issuer).

The single `issuer-conformance` example (`main.rs` + modules in this folder)
serves both the `oid4vci-1_0-issuer-*` and `fapi2-security-profile-final-*` test
plans — they exercise the same server.

## Prerequisites

You'll need the following:

- `step-cli` (called `step` on macOS).
- `jq`
- `sponge`

## Setup

1. Go to the OpenID Foundation conformance suite website:

<https://demo.certification.openid.net/>

2. Create a new test plan and select an **OID4VCI issuer** test plan.
3. Run `setup.sh` to generate the cryptographic material and the `test.json`
   configuration:

   ```bash
   examples/issuer-conformance/setup.sh
   ```

4. Copy the generated `test.json` into the `JSON` tab of the "Configure Test"
   section, then create the test plan.

## Running

The conformance suite runs in the cloud, so it must be able to reach this
issuer. Expose it with a tunnel (e.g. ngrok) and pass the public URL via
`--public-url` — it becomes the Credential Issuer identifier and must match
`vci.credential_issuer_url` in `test.json`.

```bash
# 1. Start a tunnel to the local port (default 3000):
ngrok http 3000

# 2. Generate test.json with that public URL baked into vci.credential_issuer_url:
examples/issuer-conformance/setup.sh --public-url https://YOUR_NGROK_URL.ngrok-free.app

# 3. Run the issuer:
cargo run --example issuer-conformance --features axum -- \
  --public-url https://65ad-2001-1284-f50e-21d4-1dfd-7ac1-841c-fd23.ngrok-free.app
```

Health check: `curl https://YOUR_NGROK_URL.ngrok-free.app/health` (expects `200`).

The one running server supports every flow without a restart:

- **Wallet-initiated** and **Pre-Authorized Code** flows are driven entirely by
  the wallet through the HTTP endpoints — nothing else to do.
- **Issuer-initiated** flow: the server prompts on the terminal for the wallet's
  `credential_offer_endpoint` (the value the conformance test exports). Paste it
  and the server builds and delivers a Credential Offer to it. Other flows just
  ignore the prompt.

```
credential_offer_endpoint> https://demo.certification.openid.net/test/a/<alias>/credential_offer
Delivered Credential Offer to https://.../credential_offer (HTTP 200 OK).
```

| Flag                 | Description                                                                                                                                                                                    |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-P, --public-url`   | Public URL the suite reaches the issuer at (the tunnel URL).                                                                                                                                   |
| `-p, --port`         | Local listening port (default `3000`).                                                                                                                                                         |
| `-k, --issuer-jwk`   | Credential signing JWK (default `crypto/issuer/jwk.json`, has `x5c`).                                                                                                                          |
| `-a, --attester-jwk` | Trusted Client Attester public JWK (default `crypto/attester/jwk.pub.json`).                                                                                                                   |
| `-r, --redirect-uri` | Registered client redirect URI(s); repeatable. When set, PAR rejects any other `redirect_uri`. Use the suite's callback (e.g. `https://www.certification.openid.net/test/a/<alias>/callback`). |

## Configuration fields

`setup.sh` fills the fields derived from the generated cryptographic material;
the issuer-server-dependent `vci.*` fields are left as placeholders for you to
edit in `test.json` before uploading.

| `test.json` key                           | Filled by `setup.sh` from            | Notes                                                                                   |
| ----------------------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------- |
| `credential.trust_anchor_pem`             | `ca/cert.pem`                        | Credential Trust Anchor                                                                 |
| `credential.status_list_trust_anchor_pem` | `ca/cert.pem`                        | Status List Trust Anchor                                                                |
| `client.client_id`                        | `wallet/did`                         |                                                                                         |
| `client_attestation.attester_jwks`        | `attester/jwk.pub.json`              | wrapped as `{ "keys": [ … ] }`                                                          |
| `client_attestation.issuer`               | `attester/did`                       | Client Attestation Issuer                                                               |
| `client_attestation.key_attestation_jwks` | `key-attestation/jwk.pub.json`       | wrapped as `{ "keys": [ … ] }`                                                          |
| `vci.credential_issuer_url`               | `--public-url` (or edit manually)    | public URL of your running issuer                                                       |
| `vci.credential_configuration_id`         | — (preset `eu.europa.ec.eudi.pid.1`) | edit to match your issuer's config                                                      |
| `vci.credential_proof_type_hint`          | — (optional, empty)                  | empty → suite uses the first proof type in the credential config                        |
| `vci.authorization_server`                | `--public-url` (issuer is the AS)    | the AS the suite selects; must be listed in the issuer metadata `authorization_servers` |
| `client2.client_id`                       | `wallet2/did`                        | second client identity (e.g. happy-flow-multiple-clients)                               |

> The issuer's Credential **signing** key (`issuer/jwk.json`, with its `x5c`
> chaining to `ca/cert.pem`) is loaded by the issuer server itself, not put in
> `test.json`; the suite only needs the trust anchor (`ca/cert.pem`).

## Tests requiring TLS cipher configuration (BCP 195)

A few tests assert the TLS layer itself, not the protocol. FAPI2 §5.2.2
(BCP 195 / RFC 9325) requires the server to accept **only** the recommended
TLS 1.2 cipher suites:

```
ECDHE-ECDSA-AES128-GCM-SHA256   ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-RSA-AES128-GCM-SHA256     ECDHE-RSA-AES256-GCM-SHA384
DHE-RSA-AES128-GCM-SHA256       DHE-RSA-AES256-GCM-SHA384
```

(plus the TLS 1.3 suites). These tests assert on whatever terminates TLS at the
public `:443` endpoint, and all fail on the same assertion,
`RequireOnlyBCP195RecommendedCiphersForTLS12`:

- `oid4vci-1_0-issuer-happy-flow-additional-requests`
- `fapi2-security-profile-final-happy-flow`
- `fapi2-security-profile-final-ensure-holder-of-key-required`

This issuer speaks **plain HTTP** and never terminates TLS, so the negotiated
cipher is entirely the public TLS terminator's. A plain `ngrok http` tunnel
terminates TLS at ngrok's edge with ciphers you cannot restrict, so these tests
fail on `RequireOnlyBCP195RecommendedCiphersForTLS12` even though every protocol
assertion passes. The conformance suite **cannot produce a certification package
while these are FAILED**, so they must be made to pass — a reviewer note does
not unblock the package for a `FAILED`/`INTERRUPTED` test.

To pass, terminate TLS yourself with a BCP 195-compliant configuration and a
publicly trusted certificate for your own domain, exposed through a **pass-through**
tunnel (raw TCP — e.g. `ngrok tls`, or self-hosted `frp`/`rathole`/`sish`) or a
public IP, so your terminator — not the tunnel — performs the handshake.

Example nginx in front of the issuer (`127.0.0.1:3000`):

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name issuer.example.com;

    ssl_certificate     /etc/letsencrypt/live/issuer.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/issuer.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    # Offer only ECDHE+AES-GCM (a subset of the permitted list, so no dhparam
    # is needed); any non-permitted cipher the suite offers is then refused.
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    }
}
```

Then run with `--public-url https://issuer.example.com` and set
`vci.credential_issuer_url` to the same. Only the HTTPS certificate is tied to
the domain; the OID4VCI signing/attester material under `crypto/` is
domain-independent and does **not** need regenerating. Verify before running the
plan:

```bash
# A non-permitted cipher must be refused:
openssl s_client -connect issuer.example.com:443 -cipher 'AES128-SHA' </dev/null
# Enumerate what is actually accepted:
nmap --script ssl-enum-ciphers -p 443 issuer.example.com
```
