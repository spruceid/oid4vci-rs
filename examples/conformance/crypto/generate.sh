#!/bin/bash
cd $(dirname "$0")

# Re-create sub-directories.
rm -rf ca attester issuer wallet
mkdir -p ca attester issuer wallet

# Create root CA.
step-cli certificate create "Test CA" ca/cert.pem ca/key.pem --profile root-ca --subtle --insecure --no-password -f

# Create Client Attester JWK.
step-cli crypto jwk create attester/jwk.pub.json attester/jwk.json --insecure --no-password -f

# Compute Client Attester DID.
attester_did="did:jwk:$(cat attester/jwk.pub.json | jq -Sc 'del(.kid)' | tr -d '\n' | step-cli base64 -u -r)"

# Save Client Attester DID.
printf $attester_did > attester/did

# Convert Client Attester JWK to PEM.
step-cli crypto key format attester/jwk.json -f --pem --out attester/key.pem --insecure --no-password

# Create Client Attester X.509 Certificate.
step-cli certificate create "Wallet" attester/cert.pem --key attester/key.pem --ca ca/cert.pem --ca-key ca/key.pem --profile leaf -f

# Add the X.509 Certificate to the Client Attester JWK.
jq --arg id "${attester_did}#0" --arg cert "$(cat attester/cert.pem | step-cli base64 -r)" '.kid = $id | .x5c = [$cert]' attester/jwk.json | sponge attester/jwk.json
jq --arg id "${attester_did}#0" --arg cert "$(cat attester/cert.pem | step-cli base64 -r)" '.kid = $id | .x5c = [$cert]' attester/jwk.pub.json | sponge attester/jwk.pub.json

# Create Issuer JWK.
step-cli crypto jwk create issuer/jwk.pub.json issuer/jwk.json --insecure --no-password -f

# Convert Issuer JWK to PEM.
step-cli crypto key format issuer/jwk.json --pem --out issuer/key.pem --insecure --no-password --f

# Create Issuer X.509 Certificate.
step-cli certificate create "Issuer" issuer/cert.pem --key issuer/key.pem --ca ca/cert.pem --ca-key ca/key.pem --profile leaf -f

# Add the X.509 Certificate to the Issuer JWK.
jq --arg cert "$(cat issuer/cert.pem | step-cli base64 -r)" '.x5c = [$cert]' issuer/jwk.json | sponge issuer/jwk.json
jq --arg cert "$(cat issuer/cert.pem | step-cli base64 -r)" '.x5c = [$cert]' issuer/jwk.pub.json | sponge issuer/jwk.pub.json

# Generate Wallet JWK.
step-cli crypto jwk create wallet/jwk.pub.json wallet/jwk.json --insecure --no-password -f

# Compute Wallet DID.
wallet_did="did:jwk:$(cat wallet/jwk.pub.json | jq -Sc 'del(.kid)' | tr -d '\n' | step-cli base64 -u -r)"

# Set Wallet Key ID.
jq --arg id "${wallet_did}#0" '.kid = $id' wallet/jwk.json | sponge wallet/jwk.json
jq --arg id "${wallet_did}#0" '.kid = $id' wallet/jwk.pub.json | sponge wallet/jwk.pub.json

# Print Wallet DID.
printf $wallet_did > wallet/did