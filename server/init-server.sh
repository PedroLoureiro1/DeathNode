#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

chmod 600 certs/server.key certs/db_client.key

# Configure firewall
chmod +x firewall_server.sh
sudo ./firewall_server.sh

. ./server_env.sh

python3 src/server.py
