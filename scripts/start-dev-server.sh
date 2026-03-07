#!/bin/bash
# start-dev-server.sh — Generates config.yaml with a fresh bcrypt hash and
# starts the Go development server. Used by playwright.config.ts webServer.
#
# Usage: ./scripts/start-dev-server.sh

set -euo pipefail

# Generate config.yaml with the E2E admin credentials.
go run ./cmd/genhash write-config \
  --username "admin@test.local" \
  --password "test-password" \
  --issuer "https://auth.example.com" \
  --jwt-key-path "keys/private.pem" \
  --admin-token "admin-bearer-token-placeholder-dld682" \
  --output config.yaml

echo "config.yaml updated with fresh bcrypt hash"

# Start the server.
exec env SEED_TEST_CLIENT=1 REFRESH_TOKEN_LIFESPAN=2s go run ./cmd/server
