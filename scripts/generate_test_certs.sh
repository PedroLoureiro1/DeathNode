#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$(dirname "$0")/../shared/test_secrets"
PROJECT_ROOT="$(dirname "$0")/.."
SERVER_CERT_DIR="$PROJECT_ROOT/server/certs"
VIGILANT_CERT_DIR="$PROJECT_ROOT/vigilant/certs"
DB_CERT_DIR="$PROJECT_ROOT/db/certs"

PUBLIC_IP="${1:-192.168.100.2}"
SERVER_PRIVATE_IP="${2:-192.168.0.10}"
SERVER_VIGILANT_IP="${3:-192.168.100.2}"
VIGILANT_SERVER_IP="${4:-192.168.100.1}"
VIGILANT_PEERS_IP="${5:-192.168.200.1}"
DB_PRIVATE_IP="${6:-192.168.0.100}"
DNS_NAME="localhost"
NUM_PEERS="${7:-2}"  # Number of peer certificates to generate (default: 2)

mkdir -p "$OUT_DIR" "$SERVER_CERT_DIR" "$VIGILANT_CERT_DIR" "$DB_CERT_DIR"

echo "Generating certificates..."
echo "  Server: DB=$SERVER_PRIVATE_IP, Vigilant=$SERVER_VIGILANT_IP"
echo "  Vigilant: Server=$VIGILANT_SERVER_IP, Peers=$VIGILANT_PEERS_IP"
echo "  Database: Private=$DB_PRIVATE_IP"

# Generate CA with proper extensions for certificate signing
openssl genrsa -out "$OUT_DIR/ca.key" 4096 2>/dev/null

cat > "$OUT_DIR/ca_ext.cnf" <<EOF
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer:always
EOF

openssl req -x509 -new -nodes -key "$OUT_DIR/ca.key" -sha256 -days 3650 \
  -subj "/C=PT/ST=Lisboa/L=Lisboa/O=DeathNode/CN=DeathNode-CA" \
  -extensions v3_ca -config <(cat /etc/ssl/openssl.cnf "$OUT_DIR/ca_ext.cnf") \
  -out "$OUT_DIR/ca.pem" 2>/dev/null

# Generate server certificate (for HTTPS with clients)
openssl genrsa -out "$SERVER_CERT_DIR/server.key" 4096 2>/dev/null
openssl req -new -key "$SERVER_CERT_DIR/server.key" \
  -subj "/C=PT/ST=Lisboa/L=Lisboa/O=DeathNode/CN=deathnode-server" \
  -out "$OUT_DIR/server.csr" 2>/dev/null

cat > "$OUT_DIR/server_ext.cnf" <<EOF
subjectAltName = IP:$SERVER_VIGILANT_IP, IP:$SERVER_PRIVATE_IP, DNS:$DNS_NAME
EOF

openssl x509 -req -in "$OUT_DIR/server.csr" \
  -CA "$OUT_DIR/ca.pem" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
  -out "$SERVER_CERT_DIR/server.pem" -days 365 -sha256 \
  -extfile "$OUT_DIR/server_ext.cnf" 2>/dev/null

# Keep copy in shared for convenience
cp -f "$SERVER_CERT_DIR/server.pem" "$OUT_DIR/server.pem"

# Set permissions for server key
chmod 600 "$SERVER_CERT_DIR/server.key"

# Generate vigilant certificate (for HTTPS with clients - acts as proxy)
openssl genrsa -out "$VIGILANT_CERT_DIR/vigilant.key" 4096 2>/dev/null
openssl req -new -key "$VIGILANT_CERT_DIR/vigilant.key" \
  -subj "/C=PT/ST=Lisboa/L=Lisboa/O=DeathNode/CN=deathnode-vigilant" \
  -out "$OUT_DIR/vigilant.csr" 2>/dev/null

cat > "$OUT_DIR/vigilant_ext.cnf" <<EOF
subjectAltName = IP:$VIGILANT_SERVER_IP, IP:$VIGILANT_PEERS_IP, DNS:$DNS_NAME
EOF

openssl x509 -req -in "$OUT_DIR/vigilant.csr" \
  -CA "$OUT_DIR/ca.pem" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
  -out "$VIGILANT_CERT_DIR/vigilant.pem" -days 365 -sha256 \
  -extfile "$OUT_DIR/vigilant_ext.cnf" 2>/dev/null

# Keep copy in shared for convenience
cp -f "$VIGILANT_CERT_DIR/vigilant.pem" "$OUT_DIR/vigilant.pem"

# Set permissions for vigilant key
chmod 600 "$VIGILANT_CERT_DIR/vigilant.key"

# Generate DB client certificate (for server to authenticate to DB as app_worker)
openssl genrsa -out "$SERVER_CERT_DIR/db_client.key" 4096 2>/dev/null
openssl req -new -key "$SERVER_CERT_DIR/db_client.key" \
  -subj "/C=PT/ST=Lisboa/L=Lisboa/O=DeathNode/CN=app_worker" \
  -out "$OUT_DIR/db_client.csr" 2>/dev/null

openssl x509 -req -in "$OUT_DIR/db_client.csr" \
  -CA "$OUT_DIR/ca.pem" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
  -out "$SERVER_CERT_DIR/db_client.pem" -days 365 -sha256 2>/dev/null

chmod 600 "$SERVER_CERT_DIR/db_client.key"

# Generate peer client certificates (for mTLS to vigilant)
for i in $(seq 1 "$NUM_PEERS"); do
  PEER_DIR="$OUT_DIR/peer$i"
  mkdir -p "$PEER_DIR"
  
  # Generate private key
  openssl genrsa -out "$PEER_DIR/client.key" 4096 2>/dev/null
  chmod 600 "$PEER_DIR/client.key" 2>/dev/null || true
  
  # Generate certificate signing request
  openssl req -new -key "$PEER_DIR/client.key" \
    -subj "/C=PT/ST=Lisboa/L=Lisboa/O=DeathNode/CN=peer$i" \
    -out "$OUT_DIR/peer$i.csr" 2>/dev/null
  
  # Sign certificate with CA
  openssl x509 -req -in "$OUT_DIR/peer$i.csr" \
    -CA "$OUT_DIR/ca.pem" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
    -out "$PEER_DIR/client.pem" -days 365 -sha256 2>/dev/null
  
  chmod 644 "$PEER_DIR/client.pem" 2>/dev/null || true
done

# Generate database certificate (server certificate for PostgreSQL)
openssl genrsa -out "$DB_CERT_DIR/db.key" 4096 2>/dev/null
openssl req -new -key "$DB_CERT_DIR/db.key" \
  -subj "/C=PT/ST=Lisboa/L=Lisboa/O=DeathNode/CN=deathnode-db" \
  -out "$OUT_DIR/db.csr" 2>/dev/null

cat > "$OUT_DIR/db_ext.cnf" <<EOF
subjectAltName = IP:$DB_PRIVATE_IP, DNS:$DNS_NAME, DNS:deathnode-db
EOF

openssl x509 -req -in "$OUT_DIR/db.csr" \
  -CA "$OUT_DIR/ca.pem" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
  -out "$DB_CERT_DIR/db.pem" -days 365 -sha256 \
  -extfile "$OUT_DIR/db_ext.cnf" 2>/dev/null

# Keep copy in shared for convenience
cp -f "$DB_CERT_DIR/db.pem" "$OUT_DIR/db.pem"

# Set permissions for database key
chmod 600 "$DB_CERT_DIR/db.key"

# Set permissions for CA key
chmod 600 "$OUT_DIR"/*.key

# Clean up temporary files
rm -f "$OUT_DIR/server.csr" "$OUT_DIR/server_ext.cnf" "$OUT_DIR/vigilant.csr" "$OUT_DIR/vigilant_ext.cnf" "$OUT_DIR/db.csr" "$OUT_DIR/db_ext.cnf" "$OUT_DIR/db_client.csr" "$OUT_DIR/ca_ext.cnf" "$OUT_DIR/peer"*.csr

echo "  Certificates generated successfully"
echo "  CA: shared/test_secrets/ca.pem"
echo "  Server: server/certs/{server.pem,server.key,db_client.pem,db_client.key}"
echo "  Vigilant: vigilant/certs/{vigilant.pem,vigilant.key}"
echo "  Database: db/certs/{db.pem,db.key}"
for i in $(seq 1 "$NUM_PEERS"); do
  echo "  Peer$i: shared/test_secrets/peer$i/{client.key,client.pem}"
done

SEED_FILE="$PROJECT_ROOT/db/seed.sql"
if [ -f "$SEED_FILE" ]; then

  echo "-- Auto-generated test data" > "$SEED_FILE"
  echo "-- Private keys stored in shared/test_secrets/peer* folders" >> "$SEED_FILE"
  echo "" >> "$SEED_FILE"
  echo "DELETE FROM users;" >> "$SEED_FILE"

  for i in $(seq 1 "$NUM_PEERS"); do
    PEER_DIR="$OUT_DIR/peer$i"
    # Extract public key from private key (since we no longer generate certificates)
    PUBKEY="$(openssl rsa -in "$PEER_DIR/client.key" -pubout 2>/dev/null || true)"
    if [ -z "$PUBKEY" ]; then
      echo "Warning: could not extract public key for peer$i" >&2
      continue
    fi

    # Append INSERT using printf to preserve newlines and avoid shell $$ expansion
    printf '\nINSERT INTO users (username, public_key) VALUES (\047peer%s\047, $$\n%s\n$$);\n' "$i" "$PUBKEY" >> "$SEED_FILE"
  done

  echo "  Updated $SEED_FILE with $NUM_PEERS user(s)"
else
  echo "Warning: seed file $SEED_FILE not found, skipping update" >&2
fi
