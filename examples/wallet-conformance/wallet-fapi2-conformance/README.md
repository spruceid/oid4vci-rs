# `wallet-fapi2-conformance`

A wallet that drives the bare **OAuth2 / FAPI2 Security Profile** flow against
the OpenID Foundation conformance suite. HAIP requires compliance with the FAPI2
Security Profile (HAIP §4), so the OID4VCI wallet test plan includes the
`fapi2-security-profile-final-client-test-*` modules to exercise the underlying
OAuth2 layer independently of credential issuance.

Unlike [`wallet-oid4vci-conformance`](../wallet-oid4vci-conformance/), there is
**no Credential Offer**. The flow is:

1. discover the Authorization Server metadata from the `issuer` (RFC 8414);
2. push an Authorization Request (PAR) with PKCE `S256`, Client Attestation and
   DPoP, then visit the Authorization Endpoint (it redirects back immediately —
   "Browser Interaction: None");
3. validate the Authorization Response `state` (RFC 6749) and `iss` (RFC 9207)
   before exchanging the code at the Token Endpoint;
4. make a DPoP-bound `GET` to the protected resource endpoint.

## Setup

The cryptographic material and `test.json` are shared with the other wallet
example — generate them as described in
[`../README.md`](../README.md) (use `--haip`).

## Running

Each module exports the values you need on the running test's page: `issuer` (or
`credential_issuer`) and a resource endpoint (`accounts_endpoint` / userinfo).
Pass them as `--issuer` and `--resource-url`:

```bash
cargo run --example wallet-fapi2-conformance -- \
  -t examples/wallet-conformance/crypto/attester/jwk.json \
  -k examples/wallet-conformance/crypto/wallet/jwk.json \
  --issuer       https://demo.certification.openid.net/test/<test_id>/ \
  --resource-url https://demo.certification.openid.net/test/<test_id>/open-banking/v1.1/accounts \
  --scope accounts
```

The same command drives every module in the suite — the suite injects the fault
and checks the wallet reacts correctly.

### Modules and how the wallet satisfies them

| Module                                                                                     | Expected wallet behaviour                                        | Enforced by                                           |
| ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | ----------------------------------------------------- |
| `happy-path`, `happy-path-no-dpop-nonce`                                                   | Complete discovery → PAR → token → resource GET.                 | this example + lib DPoP nonce retry                   |
| `discovery-issuer-mismatch`                                                                | Reject AS metadata whose `issuer` ≠ requested issuer.            | `open_auth2` discovery (RFC 8414)                     |
| `invalid-authorization-response-iss`, `remove-authorization-response-iss`                  | Reject a missing/mismatched `iss` in the Authorization Response. | `common::obtain_authorization_code` (RFC 9207)        |
| `ensure-authorization-response-with-invalid-state-fails`, `...invalid-missing-state-fails` | Reject a missing/mismatched `state`.                             | `common::obtain_authorization_code` (RFC 6749)        |
| `token-endpoint-response-without-expires_in`                                               | Accept a token response without `expires_in` (it is optional).   | `open_auth2::TokenResponse`                           |
| `token-type-case-insensitivity`, `rs-dpop-auth-scheme-case-insensitivity`                  | Treat `token_type` / DPoP auth scheme case-insensitively.        | DPoP proof is always sent for `sender_constrain=dpop` |

### Options

| Flag                 | Description                                                                       |
| -------------------- | --------------------------------------------------------------------------------- |
| `-i, --issuer`       | Authorization Server / issuer identifier (AS metadata discovered from it).        |
| `-r, --resource-url` | Protected resource endpoint to GET (accounts / userinfo).                         |
| `-s, --scope`        | Requested scope (optional; sent only when given). `plain_oauth` rejects `openid`. |
| `-a, --auto-auth`    | Query the Authorization Endpoint automatically (expects redirect).                |
| `-k, --jwk`          | Wallet signing JWK (random if unset).                                             |
| `-t, --attester-jwk` | Client attester JWK (client attestation disabled if unset).                       |
| `-p, --port`         | Loopback port for the redirect listener (default `1234`).                         |
| `-u, --url`          | Override the redirect base URL (default `http://127.0.0.1:{PORT}`).               |

> The `--port`/`--url` redirect URL must match the `client.redirect_uri`
> registered in `test.json`.
