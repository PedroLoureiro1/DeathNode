#!/bin/bash

set -e

CERTS_DIR="certs"

# Check if certs directory exists and has certificates
if [ ! -d "$CERTS_DIR" ] || [ -z "$(ls -A "$CERTS_DIR" 2>/dev/null)" ]; then
    echo "[ERROR] Certificates not found!"
    echo ""
    echo "Please copy your peer certificates first:"
    echo "  cp ../shared/test_secrets/peer{number}/* certs/"
    echo ""
    echo "Refer to client/README.md for complete setup instructions."
    exit 1
fi

echo "[OK] Certificates found in certs/"
echo ""

# Configure firewall
    chmod +x "firewall_peer.sh"
    sudo "./firewall_peer.sh"

echo ""
echo "The client is a CLI tool - it does not run as a service."
echo "Use commands to interact with the system:"
echo ""

python3 src/main.py -h

