#!/bin/bash
cd $(dirname "$0")

# Generate cryptographic material.
echo "Generating cryptographic material..."
crypto/generate.sh

echo "Building test configuration..."
cat test.template.json | jq --argjson client_key "$(cat crypto/wallet/jwk.pub.json)" \
   --arg client_id "$(cat crypto/wallet/did)" \
   --argjson signing_jwk "$(cat crypto/issuer/jwk.json)" \
   --arg attester_did "$(cat crypto/attester/did)" \
   --arg root_cert "$(cat crypto/ca/cert.pem)" \
   '.client.jwks.keys = [$client_key] | .client.client_id = $client_id | .credential.signing_jwk = $signing_jwk | .server.jwks.keys = [$signing_jwk] | .vci.client_attestation_issuer = $attester_did | .vci.client_attestation_trust_anchor = $root_cert' \
   > test.json

echo "Test configuration available at:"
echo "$(dirname $0)/test.json"