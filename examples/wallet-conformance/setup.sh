#!/bin/bash
cd $(dirname "$0")

# Parse options.
#
# --haip   Enable the HAIP 1.0 profile. Adds the root-level `client_attestation`
#          object (issuer, trust_anchor, key_attestation_trust_anchor_pem) to the
#          generated test configuration. Without it, the conformance suite is
#          configured for the base OID4VCI wallet test plan.
haip=false
for arg in "$@"; do
  case "$arg" in
    --haip) haip=true ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

# Generate cryptographic material.
echo "Generating cryptographic material..."
crypto/generate.sh

echo "Building test configuration..."

# Base jq filter, shared by all profiles.
filter='.client.jwks.keys = [$client_key]
  | .client.client_id = $client_id
  | .credential.signing_jwk = $signing_jwk
  | .server.jwks.keys = [$signing_jwk]
  | .vci.client_attestation_issuer = $attester_did
  | .vci.client_attestation_trust_anchor = $root_cert'

if [ "$haip" = true ]; then
  echo "  (HAIP 1.0 profile enabled)"
  # HAIP requires the root-level `client_attestation` object.
  filter="$filter
    | .client_attestation.issuer = \$attester_did
    | .client_attestation.trust_anchor = \$root_cert
    | .client_attestation.key_attestation_trust_anchor_pem = \$root_cert"
else
  # Drop the template placeholder when not running the HAIP profile.
  filter="$filter | del(.client_attestation)"
fi

cat test.template.json | jq --argjson client_key "$(cat crypto/wallet/jwk.pub.json)" \
   --arg client_id "$(cat crypto/wallet/did)" \
   --argjson signing_jwk "$(cat crypto/issuer/jwk.json)" \
   --arg attester_did "$(cat crypto/attester/did)" \
   --arg root_cert "$(cat crypto/ca/cert.pem)" \
   "$filter" \
   > test.json

echo "Test configuration available at:"
echo "$(dirname $0)/test.json"
