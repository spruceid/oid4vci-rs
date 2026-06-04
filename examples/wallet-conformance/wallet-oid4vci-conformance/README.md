# `wallet-oid4vci-conformance`

A HAIP wallet that drives the **OID4VCI 1.0 credential issuance** flow against
the OpenID Foundation conformance suite (the suite emulates the Credential
Issuer and Authorization Server).

It covers the `oid4vci-1_0-wallet-test-*` modules: resolving a Credential Offer,
the Pre-Authorized Code and Authorization Code (with PAR) grants, the nonce and
credential endpoints, and immediate or deferred credential issuance.

## Setup

The cryptographic material and the `test.json` configuration are shared by all
wallet conformance examples. Generate them as described in
[`../README.md`](../README.md) (use `--haip` for the
HAIP 1.0 profile).

## Running

Start the wallet:

```bash
cargo run --example wallet-oid4vci-conformance -- \
  -t examples/wallet-conformance/crypto/attester/jwk.json \
  -k examples/wallet-conformance/crypto/wallet/jwk.json
```

Then provide the Credential Offer that the test displays:

- **Issuer-initiated** flows: the suite shows a Credential Offer URL / QR code on
  the running test's page. Paste it at the `Enter the credential offer URL:`
  prompt (or pass it as the positional argument).
- **Pre-Authorized Code** with a Transaction Code: use `123456` when prompted
  (or pass `-c 123456`).

### Options

| Flag                 | Description                                                            |
|----------------------|------------------------------------------------------------------------|
| `<OFFER_URL>`        | Credential Offer URL (otherwise read from stdin).                      |
| `-c, --tx-code`      | Transaction Code for Pre-Authorized grants.                            |
| `-a, --auto-auth`    | Query the Authorization Endpoint automatically (expects redirect).     |
| `-k, --jwk`          | Wallet signing JWK (random if unset).                                  |
| `-t, --attester-jwk` | Client attester JWK (client attestation disabled if unset).            |
| `-p, --port`         | Loopback port for the redirect listener (default `1234`).              |
| `-u, --url`          | Override the redirect base URL (default `http://127.0.0.1:{PORT}`).    |

> The `--port`/`--url` redirect URL must match the `client.redirect_uri`
> registered in `test.json`.
