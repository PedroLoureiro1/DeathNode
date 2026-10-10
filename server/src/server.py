import os
import json
import ssl
import psycopg2
import sys
from pathlib import Path
from flask import Flask, request, jsonify
from threading import Lock

# Import deathnote_lib from shared folder (relative to project root)
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'shared'))
from deathnote_lib import compute_hash, verify_signature

app = Flask(__name__)

# Mutex lock for document upload synchronization
upload_lock = Lock()


DB_HOST = os.getenv("DB_HOST", "192.168.0.100") 
DB_NAME = os.getenv("DB_NAME", "deathnode_db")
DB_USER = os.getenv("DB_USER", "app_worker")
DB_PASS = os.getenv("DB_PASS") # export DB_PASS='AppWorkerSecret123'

# Database SSL/TLS configuration for mutual TLS
DB_SSL_MODE = os.getenv("DB_SSL_MODE", "verify-full")  # verify-full for full mTLS
DB_SSL_ROOT_CERT = os.getenv("DB_SSL_ROOT_CERT")  # CA certificate to verify DB server
DB_SSL_CERT = os.getenv("DB_SSL_CERT")  # Client certificate for mTLS
DB_SSL_KEY = os.getenv("DB_SSL_KEY")  # Client private key for mTLS

def get_db_connection():
    if not DB_PASS:
        raise ValueError("ERRO CRÍTICO: A variável de ambiente DB_PASS não está definida!")
    
    # Build SSL parameters
    ssl_params = {}
    
    if DB_SSL_MODE and DB_SSL_MODE != 'disable':
        # Enable SSL/TLS for database connection
        ssl_params['sslmode'] = DB_SSL_MODE
        
        if DB_SSL_MODE in ('verify-ca', 'verify-full'):
            if not DB_SSL_ROOT_CERT:
                raise ValueError(
                    f"DB_SSL_ROOT_CERT is required for sslmode={DB_SSL_MODE}"
                )
            if not os.path.isfile(DB_SSL_ROOT_CERT):
                raise FileNotFoundError(
                    f"DB root certificate not found: {DB_SSL_ROOT_CERT}"
                )
            ssl_params['sslrootcert'] = DB_SSL_ROOT_CERT
        
        # For mutual TLS, client certificate and key are REQUIRED
        if DB_SSL_CERT and DB_SSL_KEY:
            if not os.path.isfile(DB_SSL_CERT):
                raise FileNotFoundError(
                    f"DB client certificate not found: {DB_SSL_CERT}"
                )
            if not os.path.isfile(DB_SSL_KEY):
                raise FileNotFoundError(
                    f"DB client key not found: {DB_SSL_KEY}"
                )
            ssl_params['sslcert'] = DB_SSL_CERT
            ssl_params['sslkey'] = DB_SSL_KEY
        elif DB_SSL_MODE in ('verify-ca', 'verify-full'):
            # Warn if mTLS certificates are not configured
            print(
                f"WARNING: DB_SSL_CERT and DB_SSL_KEY not set. "
                f"Server will verify DB, but DB won't verify server (one-way TLS).",
                file=sys.stderr
            )
    
    # Log connection attempt
    print(f"[DB] Connecting to {DB_HOST}:{DB_NAME} as {DB_USER}", flush=True)
    print(f"[DB] SSL Mode: {DB_SSL_MODE}", flush=True)
    if ssl_params:
        print(f"[DB] SSL Params: {list(ssl_params.keys())}", flush=True)
    
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            **ssl_params
        )
        print(f"[DB] Connection successful!", flush=True)
        return conn
    except Exception as e:
        print(f"[DB] Connection FAILED: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        raise


def verify_cert_key_pair(cert_path: str, key_path: str) -> bool:
    """Verify that the certificate and private key form a matching pair.
    Tries to use the 'cryptography' library; if not available falls back to
    calling 'openssl' (requires openssl binary available).
    Returns True if they match, False otherwise.
    """
    try:
        # Prefer cryptography if installed
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(key_path, 'rb') as f:
            key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        cert_pub = cert.public_key()
        key_pub = key.public_key()

        # Compare public key parameters (works for RSA/ECDSA)
        cert_bytes = cert_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        key_bytes = key_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

        return cert_bytes == key_bytes
    except ImportError:
        # Fallback: use openssl to compare modulus (RSA) or return True if openssl not available
        try:
            import subprocess
            cert_mod = subprocess.check_output(["openssl", "x509", "-noout", "-modulus", "-in", cert_path])
            key_mod = subprocess.check_output(["openssl", "rsa", "-noout", "-modulus", "-in", key_path])
            return cert_mod == key_mod
        except Exception:
            return False
    except Exception:
        return False

@app.route('/users', methods=['GET'])
def get_users():
    client_ip = request.remote_addr
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT username, public_key FROM users;')
        users = cur.fetchall()
        cur.close()
        conn.close()
        users_list = [{"username": u[0], "public_key": u[1]} for u in users]
        return jsonify(users_list)
    except Exception as e:
        print(f"[ERROR] /users endpoint failed: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/documents', methods=['POST'])
def upload_document():
    client_ip = request.remote_addr
    
    data = request.json

    # ACQUIRE LOCK - Only one client can upload at a time
    with upload_lock:
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Decode ciphertext for hash computation
            import base64
            encrypted_payload = data['encrypted_payload']
            ciphertext = base64.b64decode(encrypted_payload.get('ciphertext', ''))

            # MUTEX CHECK: Verify client is synchronized with server using ID only
            client_last_id = data.get('client_last_id')
            
            if client_last_id is None:
                cur.close()
                conn.close()
                return jsonify({
                    "error": "Synchronization required",
                    "reason": "client_last_id is required to ensure you're up-to-date",
                    "hint": "Call GET /documents/last to get current state"
                }), 409
            
            # Get server's current last document
            cur.execute('SELECT id FROM documents ORDER BY id DESC LIMIT 1')
            server_last = cur.fetchone()
            server_last_id = server_last[0] if server_last else 0
            
            # Check if client is synchronized (ID-based check only)
            if client_last_id != server_last_id:
                cur.close()
                conn.close()
                return jsonify({
                    "error": "Out of sync",
                    "reason": f"Your last_id={client_last_id} but server last_id={server_last_id}",
                    "server_state": {
                        "last_document_id": server_last_id,
                        "next_document_id": server_last_id + 1,
                        "total_documents": server_last_id + 1
                    },
                    "action": "Download missing documents before uploading"
                }), 409
            
            ciphertext_hash = compute_hash(ciphertext).hex()

            # Insert document with computed hash
            cur.execute(
                'INSERT INTO documents (ciphertext_hash, encrypted_payload, payload_hash, payload_signature) '
                'VALUES (%s, %s, %s, %s) RETURNING id',
                (ciphertext_hash, json.dumps(data['encrypted_payload']), data.get('payload_hash'), data.get('payload_signature'))
            )
            document_id = cur.fetchone()[0]

            conn.commit()
            cur.close()
            conn.close()
            
            return jsonify({
                "document_id": document_id,
                "ciphertext_hash": ciphertext_hash,
                "message": "Document uploaded successfully"
            }), 201

        except psycopg2.Error as e:
            print(f"[UPLOAD ERROR] Database error: {type(e).__name__}: {e}", flush=True)
            import traceback
            traceback.print_exc()
            return jsonify({
                "error": "Database error",
                "reason": str(e),
                "type": type(e).__name__
            }), 500
        except Exception as e:
            print(f"[UPLOAD ERROR] Unexpected error: {type(e).__name__}: {e}", flush=True)
            import traceback
            traceback.print_exc()
            return jsonify({
                "error": "Failed to save document",
                "reason": str(e),
                "type": type(e).__name__
            }), 500
    # LOCK RELEASED - Next client can now upload


@app.route('/documents/last', methods=['GET'])
def get_last_document():

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get last document
        cur.execute(
            'SELECT id, ciphertext_hash, created_at FROM documents '
            'ORDER BY id DESC LIMIT 1'
        )
        
        result = cur.fetchone()
        
        if not result:
            # Count total (should be 0)
            cur.execute('SELECT COUNT(*) FROM documents')
            total_docs = cur.fetchone()[0]
            cur.close()
            conn.close()
            
            return jsonify({
                "document_id": None,
                "ciphertext_hash": None,
                "total_documents": total_docs,
                "message": "No documents in database"
            })
        
        doc_id, ciphertext_hash, created_at = result
        
        # Count total documents
        cur.execute('SELECT COUNT(*) FROM documents')
        total_docs = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return jsonify({
            "document_id": doc_id,
            "ciphertext_hash": ciphertext_hash,
            "total_documents": total_docs,
            "created_at": created_at.isoformat() if created_at else None
        })
        
    except Exception as e:
        print(f"ERROR getting last document: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/documents', methods=['GET'])
def get_documents():

    try:
        since_id = request.args.get('since_id', type=int, default=0)
        limit = request.args.get('limit', type=int, default=100)
        
        # Validate limit
        if limit > 1000:
            limit = 1000
        if limit < 1:
            limit = 1
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get documents since specified ID
        cur.execute(
            'SELECT id, ciphertext_hash, encrypted_payload, payload_hash, payload_signature, created_at FROM documents '
            'WHERE id > %s ORDER BY id ASC LIMIT %s',
            (since_id, limit + 1)  # Get one extra to check if there are more
        )
        
        results = cur.fetchall()
        cur.close()
        conn.close()
        
        # Check if there are more documents
        has_more = len(results) > limit
        if has_more:
            results = results[:limit]
        
        # Build response
        documents = []
        for doc_id, ciphertext_hash, encrypted_payload, payload_hash, payload_signature, created_at in results:
            documents.append({
                "id": doc_id,
                "ciphertext_hash": ciphertext_hash,
                "encrypted_payload": encrypted_payload,
                "payload_hash": payload_hash,
                "payload_signature": payload_signature,
                "created_at": created_at.isoformat()
            })
        
        return jsonify({
            "documents": documents,
            "total_returned": len(documents),
            "has_more": has_more
        })
        
    except Exception as e:
        print(f"ERROR retrieving documents: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("=" * 60)
    print("DeathNode Server Starting...")
    print("=" * 60)
    
    # Check for insecure dev mode (no TLS)
    sirs_insecure = os.getenv('SIRS_INSECURE', '0')
    
    if sirs_insecure == '1':
        print("WARNING: Running in INSECURE mode (HTTP only) - for testing only!")
        print("Server ready on http://0.0.0.0:5000")
        print("=" * 60)
        app.run(
            host='0.0.0.0', 
            port=5000, 
            debug=False,
            threaded=True
        )
        sys.exit(0)
    
    print("Server ready on https://0.0.0.0:5000")
    print("=" * 60)
    
    # TLS configuration - MANDATORY
    tls_cert = os.getenv('SIRS_TLS_CERT')
    tls_key = os.getenv('SIRS_TLS_KEY')
    tls_ca = os.getenv('SIRS_TLS_CA')
    
    # Require TLS certificates
    if not tls_cert or not tls_key:
        print("ERROR: TLS certificate and key are required!", file=sys.stderr)
        sys.exit(1)
    
    # Require CA for client certificate verification
    if not tls_ca:
        print("ERROR: CA certificate is required for client verification!", file=sys.stderr)
        sys.exit(1)
    
    try:
        if not verify_cert_key_pair(tls_cert, tls_key):
            print(f"ERROR: TLS certificate and key do not match: {tls_cert} != {tls_key}", file=sys.stderr)
            sys.exit(1)

        app.run(
            host='0.0.0.0', 
            port=5000, 
            ssl_context=(tls_cert, tls_key),
            debug=False,
            threaded=True
        )
        
    except FileNotFoundError as e:
        print(f"ERROR: Certificate or key file not found: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to start TLS server: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
