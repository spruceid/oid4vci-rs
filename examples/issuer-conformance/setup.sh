#!/bin/bash
cd $(dirname "$0")

# Parse options.
#
# --public-url URL   The public URL the conformance suite reaches the issuer at
#                    (e.g. the ngrok URL). Fills `vci.credential_issuer_url`.
public_url=""
while [ $# -gt 0 ]; do
  case "$1" in
    --public-url) public_url="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# Generate cryptographic material.
echo "Generating cryptographic material..."
crypto/generate.sh

echo "Building test configuration..."

# Base filter: fields derived from the generated cryptographic material.
filter='.credential.trust_anchor_pem = $root_cert
  | .credential.status_list_trust_anchor_pem = $root_cert
  | .client.client_id = $client_id
  | .client2.client_id = $client2_id
  | .client_attestation.attester_jwks = {keys: [$attester_key]}
  | .client_attestation.issuer = $attester_did
  | .client_attestation.key_attestation_jwks = {keys: [$key_attestation_key]}'

if [ -n "$public_url" ]; then
  # The issuer is also the Authorization Server, so both point at the public URL.
  filter="$filter
    | .vci.credential_issuer_url = \$public_url
    | .vci.authorization_server = \$public_url"
fi

cat test.template.json | jq \
   --arg root_cert "$(cat crypto/ca/cert.pem)" \
   --arg client_id "$(cat crypto/wallet/did)" \
   --arg client2_id "$(cat crypto/wallet2/did)" \
   --argjson attester_key "$(cat crypto/attester/jwk.json)" \
   --arg attester_did "$(cat crypto/attester/did)" \
   --argjson key_attestation_key "$(cat crypto/key-attestation/jwk.json)" \
   --arg public_url "$public_url" \
   "$filter" \
   > test.json

echo "Test configuration available at:"
echo "$(dirname $0)/test.json"
echo
if [ -z "$public_url" ]; then
  echo
  echo "NOTE: vci.credential_issuer_url was not set. Pass --public-url <URL>, or"
  echo "      edit it in test.json before uploading (the others are optional and"
  echo "      have sensible defaults: credential_configuration_id, proof_type_hint,"
  echo "      authorization_server)."
fi
