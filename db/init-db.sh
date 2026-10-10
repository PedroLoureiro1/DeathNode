#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# setup firewall
sudo chmod +x firewall_db.sh
sudo ./firewall_db.sh

sudo mkdir -p /etc/ssl/certs /etc/ssl/private

# Copy CA certificate
sudo cp -f "../shared/test_secrets/ca.pem" /etc/ssl/certs/ca.pem
sudo chmod 644 /etc/ssl/certs/ca.pem

# Copy database server certificate
sudo cp -f "certs/db.pem" /etc/ssl/certs/db.pem
sudo chmod 644 /etc/ssl/certs/db.pem

# Copy database server private key
sudo cp -f "certs/db.key" /etc/ssl/private/db.key
sudo chmod 600 /etc/ssl/private/db.key
sudo chown postgres:postgres /etc/ssl/private/db.key

  echo ""
  echo "[WARNING] make sure that the configuration is complete!"
  echo ""
  echo "Please configure PostgreSQL manually according to db/README.md:"
  echo "  1. Edit /etc/postgresql/17/main/postgresql.conf"
  echo "  2. Edit /etc/postgresql/17/main/pg_hba.conf"
  echo "  3. Restart PostgreSQL: sudo systemctl restart postgresql"
  echo ""

is_active() {
  systemctl is-active --quiet "${1}" 2>/dev/null
}

SERVICE_NAME="postgresql"
if ! is_active "$SERVICE_NAME" && ! is_active "postgres"; then
  if sudo systemctl start "$SERVICE_NAME" 2>/dev/null; then
    echo "Started $SERVICE_NAME"
  else
    sudo systemctl start postgres
  fi
else
  echo "PostgreSQL service is running."
fi

DB_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='deathnode_db'" || true)
if [[ "$DB_EXISTS" == "0" ]]; then
  sudo -u postgres psql -f "$SCRIPT_DIR/schema.sql"
fi

USERS_TABLE_EXISTS=$(sudo -u postgres psql -d deathnode_db -tAc "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='users');" 2>/dev/null || true)
USERS_TABLE_EXISTS=$(echo "$USERS_TABLE_EXISTS" | tr -d '[:space:]')
if [[ "$USERS_TABLE_EXISTS" == "t" || "$USERS_TABLE_EXISTS" == "true" || "$USERS_TABLE_EXISTS" == "1" ]]; then
  TOTAL_USERS_COUNT=$(sudo -u postgres psql -d deathnode_db -tAc "SELECT COUNT(*) FROM users;" 2>/dev/null || true)
  TOTAL_USERS_COUNT=$(echo "$TOTAL_USERS_COUNT" | tr -d '[:space:]')
  if [[ -z "$TOTAL_USERS_COUNT" || "$TOTAL_USERS_COUNT" == "0" ]]; then
    sudo -u postgres psql -d deathnode_db < "$SCRIPT_DIR/seed.sql"
  fi
fi

exit 0
