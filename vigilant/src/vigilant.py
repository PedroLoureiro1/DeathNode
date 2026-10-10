import os
import json
import sys
import base64
import logging
import ssl
import requests
from pathlib import Path
from flask import Flask, request, jsonify, Response
from datetime import datetime, timedelta
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'shared'))
from deathnote_lib import verify_payload_signature

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Server communication via eth0 (192.168.100.x internal network)
# Client communication via eth1 (192.168.200.x internal network)
DEATHNODE_SERVER_URL = os.getenv("DEATHNODE_SERVER_URL", "https://192.168.100.2:5000")
DEFAULT_CA = str(Path(__file__).parent.parent.parent / 'shared' / 'test_secrets' / 'ca.pem')
CA_CERT = os.getenv("CA_CERT", DEFAULT_CA)  # path to CA to verify server
VIGILANTE_CLIENT_CERT = os.getenv("VIGILANTE_CLIENT_CERT", str(Path(__file__).parent.parent / 'certs' / 'vigilant.pem'))
VIGILANTE_CLIENT_KEY = os.getenv("VIGILANTE_CLIENT_KEY", str(Path(__file__).parent.parent / 'certs' / 'vigilant.key'))

# Ban policy configuration
ENABLE_IP_BANS = os.getenv("ENABLE_IP_BANS", "1") == "1"  # '1' = track and ban by IP address
IP_BAN_THRESHOLD = int(os.getenv("IP_BAN_THRESHOLD", "5"))  # Failed attempts before IP ban
IP_BAN_WINDOW = int(os.getenv("IP_BAN_WINDOW", "300"))  # Time window in seconds (5 min default)

# In-memory user cache (loaded from server at startup)
users_cache = {}  # {username: public_key_pem}

# In-memory ban management 
banned_users = {}  # {username: expiry_timestamp or None for permanent}
banned_ips = {}  # {ip_address: expiry_timestamp or None for permanent}

# In-memory rate limiting for spam detection
user_uploads = {}  # {username: [timestamp1, timestamp2, ...]}
ip_failed_attempts = {}  # {ip_address: [(timestamp, reason), ...]}

# In-memory replay attack prevention
seen_nonces = {}  # {nonce_hex: timestamp} - tracks nonces to prevent replay attacks

def _file_exists_readable(path: str) -> bool:
    """Check if a file exists and is readable."""
    return path and os.path.isfile(path) and os.access(path, os.R_OK)

def check_tls_config():
    """Validate TLS configuration files and certificates."""
    if CA_CERT and not _file_exists_readable(CA_CERT):
        app.logger.error('CA_CERT not found or not readable: %s', CA_CERT)
    
    if not _file_exists_readable(VIGILANTE_CLIENT_CERT):
        app.logger.error('Vigilante client certificate not found or unreadable: %s', VIGILANTE_CLIENT_CERT)
    if not _file_exists_readable(VIGILANTE_CLIENT_KEY):
        app.logger.error('Vigilante client key not found or unreadable: %s', VIGILANTE_CLIENT_KEY)
    
    try:
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        if CA_CERT:
            ctx.load_verify_locations(cafile=CA_CERT)
        if _file_exists_readable(VIGILANTE_CLIENT_CERT) and _file_exists_readable(VIGILANTE_CLIENT_KEY):
            try:
                ctx.load_cert_chain(certfile=VIGILANTE_CLIENT_CERT, keyfile=VIGILANTE_CLIENT_KEY)
            except Exception as e:
                app.logger.error('Failed to load vigilante cert/key: %s', e)
    except Exception as e:
        app.logger.exception('Error creating SSLContext or loading CA/cert: %s', e)

def load_users_from_server():
    """Load users table from DeathNode server at startup (NO direct DB access)."""
    global users_cache
    
    print(f"[VIGILANT] Loading users from server {DEATHNODE_SERVER_URL}/users...", flush=True)
    
    try:
        session = requests.Session()
        
        # Determine TLS verification and client cert parameters (secure default)
        verify_param = CA_CERT if CA_CERT and _file_exists_readable(CA_CERT) else True
        cert_param = None
        if _file_exists_readable(VIGILANTE_CLIENT_CERT) and _file_exists_readable(VIGILANTE_CLIENT_KEY):
            cert_param = (VIGILANTE_CLIENT_CERT, VIGILANTE_CLIENT_KEY)
        
        response = session.get(
            f"{DEATHNODE_SERVER_URL}/users",
            verify=verify_param,
            cert=cert_param,
            timeout=10
        )
        
        if response.status_code == 200:
            users = response.json()
            users_cache = {user['username']: user['public_key'] for user in users}
            print(f"[VIGILANT]   Loaded {len(users_cache)} users into cache", flush=True)
            return True
        else:
            print(f"[VIGILANT ERROR] Failed to load users: HTTP {response.status_code}", file=sys.stderr, flush=True)
            return False
    
    except requests.exceptions.SSLError as e:
        app.logger.exception('TLS error when contacting server: %s (url=%s verify=%s cert=%s)', e, DEATHNODE_SERVER_URL, verify_param, cert_param)
        print(f"[VIGILANT ERROR] TLS error loading users: {e}", file=sys.stderr, flush=True)
        return False
    except requests.exceptions.RequestException as e:
        app.logger.exception('Error contacting server: %s (url=%s)', e, DEATHNODE_SERVER_URL)
        print(f"[VIGILANT ERROR] Failed to connect to server: {e}", file=sys.stderr, flush=True)
        return False
    except Exception as e:
        app.logger.exception('Unexpected error loading users: %s', e)
        print(f"[VIGILANT ERROR] Unexpected error loading users: {e}", file=sys.stderr, flush=True)
        return False

def get_user_public_key(username: str) -> Optional[bytes]:
    """Fetch user's public key from in-memory cache."""
    public_key_str = users_cache.get(username)
    if public_key_str:
        return public_key_str.encode('utf-8')
    return None

def find_signer_username(data: dict) -> Optional[str]:
    try:
        # Try each cached public key
        for username, public_key_str in users_cache.items():
            try:
                pub_pem = public_key_str.encode('utf-8')
                if verify_payload_signature(data, pub_pem):
                    return username
            except Exception:
                # Ignore per-key exceptions and continue searching
                continue
    except Exception as e:
        print(f"[VIGILANT ERROR] Exception while finding signer: {e}", file=sys.stderr, flush=True)
    return None

def is_banned(username: str) -> bool:
    """Check if user is banned (in-memory only)."""
    if username not in banned_users:
        return False
    
    expiry = banned_users[username]
    if expiry is None:
        return True  # Permanent ban
    
    # Check if temporary ban expired
    if datetime.now() > expiry:
        del banned_users[username]  # Remove expired ban
        return False
    
    return True

def ban_user(username: str, duration_minutes: Optional[int] = None, reason: str = None):
    """Ban user in-memory. Duration=None for permanent ban."""
    if duration_minutes is None:
        banned_users[username] = None  # Permanent
        print(f"[VIGILANT] User '{username}' PERMANENTLY BANNED. Reason: {reason}", flush=True)
    else:
        expiry = datetime.now() + timedelta(minutes=duration_minutes)
        banned_users[username] = expiry
        print(f"[VIGILANT] User '{username}' BANNED for {duration_minutes} minutes until {expiry.isoformat()}. Reason: {reason}", flush=True)

def get_ban_info(username: str) -> Optional[dict]:
    """Get ban information for a user."""
    if username not in banned_users:
        return None
    
    expiry = banned_users[username]
    return {
        "banned": True,
        "permanent": expiry is None,
        "expiry": expiry.isoformat() if expiry else None
    }

def is_ip_banned(ip: str) -> bool:
    """Check if IP is banned (in-memory only)."""
    if not ENABLE_IP_BANS or ip not in banned_ips:
        return False
    
    expiry = banned_ips[ip]
    if expiry is None:
        return True  # Permanent ban
    
    # Check if temporary ban expired
    if datetime.now() > expiry:
        del banned_ips[ip]  # Remove expired ban
        return False
    
    return True

def ban_ip(ip: str, duration_minutes: Optional[int] = None, reason: str = None):
    """Ban IP address in-memory. Duration=None for permanent ban."""
    if not ENABLE_IP_BANS:
        return
    
    if duration_minutes is None:
        banned_ips[ip] = None  # Permanent
        print(f"[VIGILANT] IP '{ip}' PERMANENTLY BANNED. Reason: {reason}", flush=True)
    else:
        expiry = datetime.now() + timedelta(minutes=duration_minutes)
        banned_ips[ip] = expiry
        print(f"[VIGILANT] IP '{ip}' BANNED for {duration_minutes} minutes until {expiry.isoformat()}. Reason: {reason}", flush=True)

def record_ip_failure(ip: str, reason: str) -> bool:
    """Record failed attempt from IP. Returns True if IP should be banned."""
    if not ENABLE_IP_BANS:
        return False
    
    now = datetime.now()
    
    # Initialize or clean old entries
    if ip not in ip_failed_attempts:
        ip_failed_attempts[ip] = []
    
    # Remove attempts outside the window
    cutoff = now - timedelta(seconds=IP_BAN_WINDOW)
    ip_failed_attempts[ip] = [(ts, r) for ts, r in ip_failed_attempts[ip] if ts > cutoff]
    
    # Record this failure
    ip_failed_attempts[ip].append((now, reason))
    
    # Check if threshold exceeded
    return len(ip_failed_attempts[ip]) >= IP_BAN_THRESHOLD

# In-memory rate limiting for spam detection
user_uploads = {}  # {username: [timestamp1, timestamp2, ...]}

def cleanup_old_nonces(max_age_minutes: int = 60):
    """Remove nonces older than max_age_minutes to prevent memory bloat."""
    global seen_nonces
    now = datetime.now()
    cutoff = now - timedelta(minutes=max_age_minutes)
    
    # Remove old entries
    expired = [nonce_hex for nonce_hex, timestamp in seen_nonces.items() if timestamp < cutoff]
    for nonce_hex in expired:
        del seen_nonces[nonce_hex]
    
    if expired:
        print(f"[VIGILANT] Cleaned up {len(expired)} expired nonces (older than {max_age_minutes} min)", flush=True)

def is_spam(username: str, threshold: int = 2, window_seconds: int = 60) -> bool:
    """Check if user is spamming based on upload rate."""
    now = datetime.now()
    if username not in user_uploads:
        user_uploads[username] = []
    
    # Remove old timestamps outside the window
    user_uploads[username] = [
        ts for ts in user_uploads[username] 
        if (now - ts).total_seconds() < window_seconds
    ]
    
    # Check if user exceeded threshold
    if len(user_uploads[username]) >= threshold:
        return True  # Spam detected
    
    # Record this upload
    user_uploads[username].append(now)
    return False


@app.route('/documents', methods=['POST'])
def vigilante_upload():
    """Intercept upload requests, check for bans/spam/fake, then forward to DeathNode server."""
    client_ip = request.remote_addr
    print(f"\n[VIGILANT] Upload request from {client_ip}", flush=True)
    
    # 0. Check if IP is banned
    if is_ip_banned(client_ip):
        expiry = banned_ips[client_ip]
        ban_type = "permanent" if expiry is None else f"until {expiry.isoformat()}"
        print(f"[VIGILANT]   IP '{client_ip}' is BANNED ({ban_type})", flush=True)
        return jsonify({
            "error": "IP banned",
            "reason": f"Your IP address has been banned due to multiple security violations",
            "details": f"Banned {ban_type}"
        }), 403
    
    data = request.json
    
    if not data or 'encrypted_payload' not in data:
        print(f"[VIGILANT ERROR] Missing encrypted_payload from {client_ip}", flush=True)
        return jsonify({"error": "Invalid format: 'encrypted_payload' required"}), 400
    
    if 'payload_signature' not in data:
        print(f"[VIGILANT ERROR] Missing payload_signature from {client_ip}", flush=True)
        return jsonify({"error": "Invalid format: 'payload_signature' required"}), 400
    
    # 1. Check for replay attack (nonce reuse)
    try:
        encrypted_payload = data['encrypted_payload']
        nonce_b64 = encrypted_payload.get('nonce', '')
        nonce = base64.b64decode(nonce_b64)
        nonce_hex = nonce.hex()
        
        if nonce_hex in seen_nonces:
            print(f"[VIGILANT] REPLAY ATTACK detected from {client_ip}: nonce {nonce_hex[:16]}... already seen", flush=True)
            ban_ip(client_ip, duration_minutes=60, reason="Replay attack")
            return jsonify({
                "error": "Replay attack detected",
                "reason": "This payload has already been submitted",
                "details": "Your IP has been banned for 60 minutes"
            }), 403
        
        # Periodically clean old nonces (every ~50 requests to avoid overhead)
        if len(seen_nonces) % 50 == 0:
            cleanup_old_nonces(max_age_minutes=60)
        
    except Exception as e:
        print(f"[VIGILANT ERROR] Failed to check replay: {e}", flush=True)
        return jsonify({"error": f"Invalid nonce format: {str(e)}"}), 400
    
    # 2. Extract and validate metadata
    metadata = encrypted_payload.get('metadata', {})
    reporter_pseudonym = metadata.get('reporter_pseudonym')
    
    if not reporter_pseudonym:
        print(f"[VIGILANT ERROR] Missing reporter_pseudonym from {client_ip}", flush=True)
        return jsonify({"error": "Missing reporter_pseudonym in metadata"}), 400
    
    print(f"[VIGILANT] Reporter: '{reporter_pseudonym}'", flush=True)
    
    # 3. Identify actual signer and check if they're banned
    print(f"[VIGILANT] Identifying actual signer...", flush=True)
    actual_signer = find_signer_username(data)
    
    if actual_signer:
        if is_banned(actual_signer):
            ban_info = get_ban_info(actual_signer)
            ban_type = "permanent" if ban_info['permanent'] else f"until {ban_info['expiry']}"
            claimed_note = f" (claimed '{reporter_pseudonym}')" if actual_signer != reporter_pseudonym else ""
            print(f"[VIGILANT]   Signer '{actual_signer}' is BANNED{claimed_note} ({ban_type})", flush=True)
            return jsonify({
                "error": "Signer is banned",
                "reason": f"The signer '{actual_signer}' is currently banned",
                "details": f"Banned {ban_type}",
                "claimed_pseudonym": reporter_pseudonym if actual_signer != reporter_pseudonym else None
            }), 403
    
    # 4. Fetch user's public key
    print(f"[VIGILANT] Fetching public key for '{reporter_pseudonym}'...", flush=True)
    public_key_pem = get_user_public_key(reporter_pseudonym)

    # If claimed pseudonym not registered, check if we already identified an impersonator
    if not public_key_pem:
        print(f"[VIGILANT] User '{reporter_pseudonym}' NOT FOUND in database", flush=True)
        if actual_signer:
            print(f"[VIGILANT] Impersonation detected: payload signed by '{actual_signer}' but claimed '{reporter_pseudonym}'", flush=True)
            ban_user(actual_signer, duration_minutes=60, reason=f"Impersonation attempt: claimed '{reporter_pseudonym}'")
            
            # Track IP failure and potentially ban IP
            if record_ip_failure(client_ip, "impersonation"):
                ban_ip(client_ip, duration_minutes=60, reason="Multiple impersonation attempts")
            
            return jsonify({
                "error": "Impersonation detected - signer banned",
                "reason": f"Payload was signed by user '{actual_signer}' but claimed reporter '{reporter_pseudonym}'.",
                "action": "Signer has been banned for 60 minutes for impersonation",
                "details": f"Banned until {(datetime.now() + timedelta(minutes=60)).isoformat()}",
                "signer": actual_signer,
                "claimed_pseudonym": reporter_pseudonym
            }), 403
        else:
            print(f"[VIGILANT]   User '{reporter_pseudonym}' NOT FOUND and signature did not match any known key", flush=True)
            print(f"[VIGILANT] Rejecting upload from IP {client_ip} (claimed: '{reporter_pseudonym}')", flush=True)
            
            # Track IP for repeated unverifiable signature attempts
            if record_ip_failure(client_ip, "unverifiable_signature"):
                ban_ip(client_ip, duration_minutes=120, reason="Multiple unverifiable signature attempts")
                return jsonify({
                    "error": "Invalid signature - IP banned",
                    "reason": "Payload signature verification failed and your IP has been banned due to multiple violations.",
                    "action": "IP banned for 120 minutes",
                    "details": f"Banned until {(datetime.now() + timedelta(minutes=120)).isoformat()}"
                }), 403
            
            return jsonify({
                "error": "Invalid signature",
                "reason": "Payload signature verification failed. Signature does not match any known user key.",
                "note": "Repeated violations from your IP may result in an IP ban"
            }), 403

    print(f"[VIGILANT] Public key retrieved (length: {len(public_key_pem)} bytes)", flush=True)

    # 5. Verify signature matches claimed user
    if actual_signer != reporter_pseudonym:
        if actual_signer is None:
            print(f"[VIGILANT] Signature does not match claimed user '{reporter_pseudonym}' or any other user", flush=True)
        else:
            print(f"[VIGILANT] IMPERSONATION detected: '{actual_signer}' claimed to be '{reporter_pseudonym}'", flush=True)
            ban_user(actual_signer, duration_minutes=60, reason=f"Impersonation: claimed '{reporter_pseudonym}'")
        
        # Track IP failure for both cases
        if record_ip_failure(client_ip, "impersonation" if actual_signer else "invalid_signature"):
            ban_ip(client_ip, duration_minutes=60 if actual_signer else 120, 
                   reason="Multiple impersonation attempts" if actual_signer else "Multiple invalid signature attempts")
            return jsonify({
                "error": "Invalid signature - IP banned" if not actual_signer else "Impersonation detected - IP banned",
                "reason": "Signature verification failed and your IP has been banned." if not actual_signer 
                         else f"User '{actual_signer}' attempted impersonation and your IP has been banned.",
                "action": f"IP banned for {60 if actual_signer else 120} minutes",
                "details": f"Banned until {(datetime.now() + timedelta(minutes=60 if actual_signer else 120)).isoformat()}",
                "signer": actual_signer,
                "claimed_pseudonym": reporter_pseudonym
            }), 403
        
        return jsonify({
            "error": "Invalid signature" if not actual_signer else "Impersonation detected - signer banned",
            "reason": "Signature does not match the claimed user or any known user." if not actual_signer
                     else f"Payload signed by '{actual_signer}' but claimed '{reporter_pseudonym}'",
            "note": "Repeated violations from your IP may result in an IP ban",
            "signer": actual_signer if actual_signer else None,
            "claimed_pseudonym": reporter_pseudonym
        }), 403
    
    print(f"[VIGILANT] ✓ Signature and pseudonym verified: '{reporter_pseudonym}'", flush=True)
    
    # 6. Check for spam (SPAM DETECTION)
    if is_spam(reporter_pseudonym):
        print(f"[VIGILANT] SPAM DETECTED ", flush=True)
        print(f"[VIGILANT] User '{reporter_pseudonym}' exceeded rate limit - BANNING for 30 minutes", flush=True)
        
        ban_user(reporter_pseudonym, duration_minutes=30, reason="Spam detected")
        
        ban_ip(client_ip, duration_minutes=30, reason=f"Spam from user '{reporter_pseudonym}'")
        
        return jsonify({
            "error": "Spam detected - user and IP banned",
            "reason": "Too many uploads in a short time period",
            "action": "User has been banned for 30 minutes for spamming. Your IP has also been banned.",
            "details": f"Banned until {(datetime.now() + timedelta(minutes=30)).isoformat()}",
            "pseudonym": reporter_pseudonym
        }), 429
    
    print(f"[VIGILANT]   Rate limit check passed", flush=True)
    # 7. Record nonce to prevent replay
    seen_nonces[nonce_hex] = datetime.now()
    print(f"[VIGILANT] Nonce recorded: {nonce_hex[:16]}... (total tracked: {len(seen_nonces)})", flush=True)
    
    # 8. Forward to main DeathNode server
    print(f"[VIGILANT] Forwarding request to DeathNode server...", flush=True)
    
    try:
        session = requests.Session()
        
        # Determine TLS verification and client cert parameters (secure default)
        verify_param = CA_CERT if CA_CERT and _file_exists_readable(CA_CERT) else True
        cert_param = None
        if _file_exists_readable(VIGILANTE_CLIENT_CERT) and _file_exists_readable(VIGILANTE_CLIENT_KEY):
            cert_param = (VIGILANTE_CLIENT_CERT, VIGILANTE_CLIENT_KEY)
        
        response = session.post(
            f"{DEATHNODE_SERVER_URL}/documents",
            json=data,
            verify=verify_param,
            cert=cert_param,
            timeout=30
        )
        
        print(f"[VIGILANT] DeathNode server response: {response.status_code}", flush=True)
        
        if response.status_code == 201:
            print(f"[VIGILANT]     UPLOAD FORWARDED SUCCESSFULLY    ", flush=True)
        
        # Forward the response back to client
        return response.json(), response.status_code
    
    except requests.exceptions.SSLError as e:
        app.logger.exception('TLS error when contacting server: %s (url=%s verify=%s cert=%s)', e, DEATHNODE_SERVER_URL, verify_param, cert_param)
        print(f"[VIGILANT ERROR] TLS error forwarding request: {e}", flush=True)
        return jsonify({
            "error": "TLS error contacting upstream server",
            "detail": str(e)
        }), 502
    except requests.exceptions.RequestException as e:
        app.logger.exception('Error contacting server: %s (url=%s)', e, DEATHNODE_SERVER_URL)
        print(f"[VIGILANT ERROR] Failed to forward request to DeathNode: {e}", flush=True)
        return jsonify({
            "error": "Failed to forward request",
            "reason": f"Could not connect to DeathNode server: {str(e)}"
        }), 502

@app.route('/')
def health_check():
    """Health check endpoint."""
    # Clean up expired bans
    now = datetime.now()
    expired = [u for u, exp in banned_users.items() if exp and exp < now]
    for u in expired:
        del banned_users[u]
    
    return jsonify({
        "status": "Vigilant Server Online",
        "role": "Gateway & Security Enforcement",
        "active_bans": len(banned_users),
        "active_ip_bans": len(banned_ips) if ENABLE_IP_BANS else 0,
        "active_users_tracked": len(user_uploads),
        "cached_users": len(users_cache),
        "ip_tracking_enabled": ENABLE_IP_BANS,
        "note": "Bans are in-memory. Users cached from server at startup."
    })

# Generic proxy for all other endpoints - forward everything to DeathNode server
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy_to_server(path):
    """Forward all other requests to DeathNode server without modification."""
    client_ip = request.remote_addr
    print(f"[VIGILANT] Proxying {request.method} /{path} from {client_ip}", flush=True)
    
    # Security: block client access to users list endpoint.
    if request.method == 'GET' and (path == 'users' or path.startswith('users/')):
        print(f"[VIGILANT] Blocking client access to /users from {client_ip}", flush=True)
        return jsonify({
            "error": "Forbidden",
            "reason": "Access to /users is restricted through the gateway"
        }), 403
    
    try:
        session = requests.Session()
        url = f"{DEATHNODE_SERVER_URL}/{path}"
        
        # Determine TLS verification and client cert parameters
        verify_param = CA_CERT if CA_CERT and _file_exists_readable(CA_CERT) else True
        cert_param = None
        if _file_exists_readable(VIGILANTE_CLIENT_CERT) and _file_exists_readable(VIGILANTE_CLIENT_KEY):
            cert_param = (VIGILANTE_CLIENT_CERT, VIGILANTE_CLIENT_KEY)
        
        # Forward request with same method, data, and query parameters
        response = session.request(
            method=request.method,
            url=url,
            json=request.json if request.is_json else None,
            data=request.data if not request.is_json else None,
            params=request.args,
            verify=verify_param,
            cert=cert_param,
            timeout=30
        )
        
        print(f"[VIGILANT] Server response: {response.status_code}", flush=True)
        
        # Return response with appropriate content type
        if response.headers.get('content-type', '').startswith('application/json'):
            return response.json(), response.status_code
        else:
            return response.content, response.status_code, {'Content-Type': response.headers.get('content-type', 'text/plain')}
    
    except requests.exceptions.SSLError as e:
        app.logger.exception('TLS error when contacting server: %s (url=%s verify=%s cert=%s)', e, url, verify_param, cert_param)
        print(f"[VIGILANT ERROR] TLS error proxying request: {e}", flush=True)
        return jsonify({
            "error": "TLS error contacting upstream server",
            "detail": str(e)
        }), 502
    except requests.exceptions.RequestException as e:
        app.logger.exception('Error contacting server: %s (url=%s)', e, url)
        print(f"[VIGILANT ERROR] Failed to proxy request: {e}", flush=True)
        return jsonify({
            "error": "Failed to forward request",
            "reason": f"Could not connect to DeathNode server: {str(e)}"
        }), 502

if __name__ == '__main__':
    print("=" * 60)
    print("Vigilant Server Starting...")
    print("=" * 60)
    print(f"Forwarding to: {DEATHNODE_SERVER_URL}")
    print("Network Configuration:")
    print("  eth0 (192.168.100.1) -> Server communication")
    print("  eth1 (192.168.200.1) -> Client communication")
    print("=" * 60)
    
    # Validate TLS configuration
    print("Checking TLS configuration...")
    check_tls_config()
    print("=" * 60)
    
    # Load users from server at startup
    if not load_users_from_server():
        print("[VIGILANT WARNING] Failed to load users from server!")
        print("[VIGILANT WARNING] Continuing anyway...")
    
    print("=" * 60)
    
    # Bind to eth1 (client-facing interface)
    vigilant_host = os.getenv('VIGILANT_HOST', '192.168.200.1')
    
    # TLS configuration for client connections
    vigilant_tls_cert = os.getenv('VIGILANT_TLS_CERT', VIGILANTE_CLIENT_CERT)
    vigilant_tls_key = os.getenv('VIGILANT_TLS_KEY', VIGILANTE_CLIENT_KEY)
    
    if vigilant_tls_cert and vigilant_tls_key and _file_exists_readable(vigilant_tls_cert) and _file_exists_readable(vigilant_tls_key):
        print(f"TLS Configuration: Enabled with mTLS (client certificate required) on {vigilant_host}:6000", flush=True)
        
        # Create SSL context for mTLS
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(vigilant_tls_cert, vigilant_tls_key)
        
        # Load CA to verify client certificates
        if CA_CERT and _file_exists_readable(CA_CERT):
            ssl_context.load_verify_locations(cafile=CA_CERT)
            ssl_context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate
            print(f"  Client certificate verification: REQUIRED (using CA: {CA_CERT})", flush=True)
        else:
            print(f"  WARNING: CA cert not found, client verification disabled", flush=True)
        
        # Disable hostname checking for client certificates (as requested)
        ssl_context.check_hostname = False
        
        app.run(
            host=vigilant_host,
            port=6000,
            ssl_context=ssl_context,
            debug=False,
            threaded=True
        )
    else:
        if vigilant_tls_cert or vigilant_tls_key:
            app.logger.error('Vigilant TLS cert or key not found or unreadable: %s %s', vigilant_tls_cert, vigilant_tls_key)
            print(f"[VIGILANT ERROR] TLS cert or key not found: {vigilant_tls_cert} {vigilant_tls_key}", flush=True)
            raise SystemExit(1)
        print(f"TLS Configuration: Disabled (running HTTP only) on {vigilant_host}:6000", flush=True)
        print("WARNING: For production, enable TLS by setting VIGILANT_TLS_CERT and VIGILANT_TLS_KEY", flush=True)
        app.run(
            host=vigilant_host,
            port=6000,
            debug=False,
            threaded=True
        )