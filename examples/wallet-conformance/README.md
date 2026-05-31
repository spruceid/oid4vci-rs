# Wallet Conformance

This directory holds the **shared setup** for the wallet conformance examples:
the cryptographic material generator and the `test.json` configuration uploaded
to the OpenID Foundation conformance suite.

Two examples run against this setup:

- [`wallet-oid4vci-conformance`](wallet-oid4vci-conformance/) — the OID4VCI
  1.0 credential issuance flow (`oid4vci-1_0-wallet-test-*` modules).
- [`wallet-fapi2-conformance`](wallet-fapi2-conformance/) — the underlying
  OAuth2 / FAPI2 Security Profile flow
  (`fapi2-security-profile-final-client-test-*` modules), required by HAIP §4.

Follow the setup below once, then see each example's README for how to run it.

## Prerequisites

You'll need the following:
- `step-cli` (called `step` on macOS).
- `jq`
- `sponge`

## Setup

1. Go to the OpenID Foundation conformance suite website:

  <https://demo.certification.openid.net/>

2. Create a new test plan.
3. Check the "Show early version tests" box.
4. Select an OID4VCI wallet test plan.
5. Use the following test parameters:

  | Parameter                          | Value                     |
  |------------------------------------|---------------------------|
  | Client Authentication Type         | `client_attestation`     |
  | Sender Constraining                | `dpop`                   |
  | Authorization Code Flow Variant    | `issuer_initiated`       |
  | Credential Format                  | any value                |
  | Authorization Request Type         | `simple`                 |
  | Credential Issuer Mode             | any value, but `immediate` is simpler |
  | VCI Profile                        | `haip`                   |
  | Request Method                     | `unsigned`               |
  | Grant Type                         | any value, but `pre_authorization_code` is simpler |
  | Credential Offer Variant           | any value                |
  | Credential Response Encryption     | `plain`                  |

6. Run the test `setup.sh` script.
  This will generate all the necessary
  cryptographic material, as well as a `test.json` file
  containing the conformance test configuration.
  
  ```bash
  examples/wallet-conformance/setup.sh
  ```

  For the HAIP 1.0 profile, pass `--haip`. This adds the root-level
  `client_attestation` object (`issuer`, `trust_anchor`, and
  `key_attestation_trust_anchor_pem`) required by the HAIP wallet test plan:

  ```bash
  examples/wallet-conformance/setup.sh --haip
  ```
7. Copy the content of the generated `test.json` file to the `JSON` tab in the "Configure Test" section.
8. Click on "Create Test Plan".

## Running a test

Run the example that matches the module under test, passing the same
cryptographic material generated above:

- OID4VCI credential issuance modules →
  [`wallet-oid4vci-conformance`](wallet-oid4vci-conformance/README.md)
- FAPI2 Security Profile modules →
  [`wallet-fapi2-conformance`](wallet-fapi2-conformance/README.md)

Both examples use the shared keys under `examples/wallet-conformance/crypto/`:

```bash
# OID4VCI credential issuance (paste the Credential Offer when prompted)
cargo run --example wallet-oid4vci-conformance -- \
  -t examples/wallet-conformance/crypto/attester/jwk.json \
  -k examples/wallet-conformance/crypto/wallet/jwk.json

# FAPI2 (pass the issuer + resource endpoint exported by the test)
cargo run --example wallet-fapi2-conformance -- \
  -t examples/wallet-conformance/crypto/attester/jwk.json \
  -k examples/wallet-conformance/crypto/wallet/jwk.json \
  --issuer <ISSUER_URL> --resource-url <RESOURCE_URL>
```