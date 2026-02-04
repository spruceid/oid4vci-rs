#!/bin/bash
# Example of an OID4VCI flow with Authorized Code grant and Push Authorization
# Request.
set -e
cd $(dirname "$0")

# Start the server.
echo "Starting server..."
cargo run -q --example server -- ../server.json --par &
pid=$!
trap "kill $pid" EXIT

# Wait until it started.
curl -s --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:3000/health
echo "Server started."

# Ask for a new credential offer.
echo "Offering credential... "
CREDENTIAL_OFFER=$(curl -s http://127.0.0.1:3000/offer/new)
echo "Credential offered."

# Get the credential, running the Authorization flow automatically.
echo "Issuing credential... "
cargo run -q --example client -- --auto-auth $CREDENTIAL_OFFER
echo "All done."