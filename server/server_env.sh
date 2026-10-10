#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_DIR="$SCRIPT_DIR"
SHARED_DIR="$PROJECT_ROOT/shared/test_secrets"

DEFAULT_DB_PASS='AppWorkerSecret123'

# Server TLS certificates (for HTTPS with clients)
export SIRS_TLS_CERT="$SERVER_DIR/certs/server.pem"
export SIRS_TLS_KEY="$SERVER_DIR/certs/server.key"
export SIRS_TLS_CA="$SHARED_DIR/ca.pem"

# Database connection settings
export DB_HOST="${DB_HOST:-192.168.0.100}"
export DB_NAME="${DB_NAME:-deathnode_db}"
export DB_USER="${DB_USER:-app_worker}"
export DB_PASS="${DB_PASS:-$DEFAULT_DB_PASS}"

# Database mTLS configuration
export DB_SSL_MODE="verify-full"
export DB_SSL_ROOT_CERT="$SHARED_DIR/ca.pem"
export DB_SSL_CERT="$SERVER_DIR/certs/db_client.pem"
export DB_SSL_KEY="$SERVER_DIR/certs/db_client.key"
