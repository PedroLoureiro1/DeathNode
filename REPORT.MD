# A10 DeathNode Project Report

## 1. Introduction

DeathNode is a secure anonymous reporting system designed to protect whistleblowers while maintaining data integrity and availability. The system enables anonymous users to submit encrypted incident reports that are stored in a distributed network with cryptographic guarantees.

**Business Scenario:**  
The DeathNode system addresses the need for secure, anonymous reporting of incidents (corruption, misconduct, security breaches) where reporter identity must be protected while ensuring report authenticity and integrity. The system uses a peer-backed architecture where each node maintains encrypted reports locally and synchronizes with a central server and other peers.

**Main Components:**
#### 1. Secure Document Format
* Custom cryptographic library implementing symmetric encryption with shared secrets, digital signatures, and hash-chain verification.

#### 2. Infrastructure
* **VM-Based Architecture** – Isolated environment featuring a dedicated database, application server, and API Gateway (Vigilant) with layered network segmentation.
* **Secure Communications** – End-to-end encryption using TLS/SSL and mutual authentication (mTLS) to enforce trusted node-to-node connectivity.

#### 3. Security Challenge
* A centralized monitoring system that audits document flow to detect spam patterns and executes temporary or permanent cryptographic bans on misbehaving members.


**System Architecture:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                            DeathNode System                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌──────────┐            ┌──────────┐            ┌──────────┐          │
│   │  Peer A  │            │ Vigilant │            │  Peer B  │          │
│   │ (Client) ├───────────►│ (Gateway)│◄───────────┤ (Client) │          │
│   │    VM    │   HTTPS    │    VM    │   HTTPS    │    VM    │          │
│   └──────────┘    mTLS    └────┬─────┘    mTLS    └──────────┘          │
│                                │                                        │
│                        Filtered Traffic Only                            │
│                  (Banned Members Blocked at Gateway)                    │
│                                │                                        │
│                          ┌─────▼─────┐                                  │
│                          │  Server   │                                  │
│                          │  (Flask)  │                                  │
│                          │    VM     │                                  │
│                          └─────┬─────┘                                  │
│                                │                                        │
│                          ┌─────▼─────┐                                  │
│                          │ PostgreSQL│                                  │
│                          │  Database │                                  │
│                          │     VM    │                                  │
│                          └───────────┘                                  │
│                                                                         │
│   Network Isolation:                                                    │
│   - DMZ: Vigilant Public Interface                                      │
│   - Internal Net: Vigilant <-> Server <-> DB (No Client Access)         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2. Project Development

### 2.1. Secure Document Format

#### 2.1.1. Design

Our secure document format implements a multi-layered cryptographic protection scheme:

**Design Principles:**
1. **Symmetric encryption with shared secret** - Reports encrypted using AES-256-GCM with keys derived from shared secrets
2. **Digital signatures** - Author authentication using RSA-PSS to prevent forgery
3. **Hash chaining** - Immutable audit trail linking documents sequentially with chain_hash
4. **Fresh randomness** - Unique nonce per encryption prevents replay attacks
5. **Reporter pseudonyms** - Document metadata includes a reporter_pseudonym field for anonymous but accountable reporting.

**Cryptographic Choices:**
- **AES-256-GCM** for symmetric encryption (authenticated encryption)
- **HKDF (HMAC-based KDF)** for deriving encryption keys from shared secrets
- **RSA-PSS with SHA-256** for digital signatures
- **SHA-256** for hashing (document content, chain linking)

**Data Format Example:**
```json
{
  "encrypted_payload": {
    "ciphertext": "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",
    "nonce": "fod51x+/nJHdFzQQ",
    "metadata": {
      "document_id": 2,
      "algorithm": "AES-256-GCM",
      "signature_algorithm": "RSA-PSS-SHA256",
      "kdf_algorithm": "HKDF-SHA256",
      "protected_at": "2025-12-19T14:43:40.694743Z",
      "reporter_pseudonym": "peer1"
    }
  },
  "payload_hash": "ibSxwcrn+5tg+InV6VyghC1pSc1rRuX8dLTwhYhCfaI=",
  "payload_signature": "HnmpLoqOzHVPXJ/U845WtmrpbRuAzq4Neec/TfpK3yRSJJvcPmtlG/Yo35ns+bqvblZ0CeHd/7zsHCgCyMT/eJCWPANabLaJHftdiLTF1h22Ulig6/Q1PIvhRUwSDhdOlXmbRuU2CXZsvDdnjf5vRrd0/XMhaZAWLXi5pTokn2Hj2gDE1XU2iWDGEjQWWuXbKbNWVRrnm0LKnQ62Ye3bJxBi9+6D1wWj8ZI4D/ZSN17yFzMgg1k3exVzS8yp0mSmEZAJjYlBxUZQWLq9Tg+Wyv90zjCxQ30ZEyJVllS5Z4KA5wWYBUX4p+dQHl0GLMkHgnH09tv9FmG1ZPCD0f9UQolZRBExZKLU0sesc9nqYQRKuRANLx1jjLW5yDJvokBf9pmPdmSr8vFs/fL9FoGk5T54Fa+KLxo6MSG7/yGVBMDk+g5Imp8IFXSgygpS+xVXh9j7zIl2ooMUYrAJXjVqUSAA0CKF0orwBWSm9siq5guPf66aXCa6Aydrd516Btg0imqVh5QzdE9puZn2YdXuiRQU8rPsYriHxCdGxd0UD153nhBkw68mSL/Ar/6rxgvz+0dhjybPsj46RYgX5uILF+voKVyokXj2LoxoFUddafccF23/464bJm6Js/elTBERKvAkNytOMnRTOMxcoJT88KXhJ0+av8Z+Rs3JO/Ptt3o="
}
```

**Stored in Database:**
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    ciphertext_hash CHAR(64) UNIQUE NOT NULL,
    encrypted_payload JSONB NOT NULL,
    payload_hash TEXT,
    payload_signature TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_documents_created_at ON documents(created_at DESC);
```

**Hash Strategy:**
* **doc_hash**: SHA-256(document_json) – Signed by the reporter; verifies the integrity of the original report content.
* **payload_hash**: SHA-256(metadata + nonce + ciphertext) – A unique identifier for the protected package used for server-side indexing.
* **chain_hash**: SHA-256(prev_chain_hash || document_bytes) – Links the current document to the entire history of the ledger.

#### 2.1.2. Implementation

**Technology Stack:**
- **Language:** Python 3.11
- **Cryptography:** `cryptography` library (v41.0+)
- **Web Framework:** Flask 3.0 for REST API
- **Database:** PostgreSQL 17 with JSONB support
- **TLS:** OpenSSL for certificate generation and verification
- **Serialization:** JSON for document format

**Implementation Components:**

1. **Core Library (`shared/deathnote_lib/`):**
   - `crypto_utils.py` - Low-level crypto primitives (AES-GCM, RSA, HKDF, hashing)
   - `protections.py` - High-level operations (protect, check, unprotect, verify_payload_signature, verify_chain)

2. **Server (`server/src/server.py`):**
   - Flask REST API with HTTPS (mTLS)
   - PostgreSQL connection with SSL/TLS
   - Endpoints: upload document, list documents, get last document id/hash
   - Mutex lock for upload synchronization

3. **Client (`client/src/main.py`):**
   - CLI for peer operations
   - Commands: protect, unprotect, check, chain-verify, upload, download, server-status
   - HTTPS client with certificate verification

**Challenges and Solutions:**

**Challenge 1: Secure shared-secret distribution**
- *Problem:* Nodes need a deterministic way to derive per-document encryption keys from a shared secret without transmitting that secret over the network.
- *Solution:* Out-of-band distribution of the pre-shared secret (manual/secure channel). Each peer derives the AES key per-document using HKDF with a document-specific salt.
- *Impact:* Shared secrets are never transmitted. This provides key diversity per document and prevents reuse of long-term AES keys while keeping key agreement simple.

**Challenge 2: Chain integrity with cumulative linking**
- *Problem:* Each document must link to entire previous chain, not just previous document
- *Solution:* `chain_hash = SHA256(prev_chain_hash || document)` - each hash builds on full history
- *Impact:* Tampering with any document breaks all subsequent chain_hash values

### 2.2. Infrastructure

#### 2.2.1. Network and Machine Setup

**Infrastructure Overview:**

The system uses four separate Virtual Machines with layered network isolation:

```
                     ┌─────────────────────┐
                     │   Client VM         │
                     │  192.168.200.2      │
                     │  eth0: Internal     │
                     └──────────┬──────────┘
                                │
                                │ HTTPS (mTLS)
                                │ Internal Network
                                │ 192.168.200.0/24
                                │
                     ┌──────────▼──────────┐
                     │  vigilant VM (API)  │
                     │  192.168.200.1      │
                     │  192.168.100.1      │
                     │  eth0: Client Net   │
                     │  eth1: Server Net   │
                     │  (Flask Proxy)      |
                     |  PORT 6000          |  
                     └──────────┬──────────┘
                                │
                                │ HTTPS (mTLS)
                                │ Internal Network
                                │ 192.168.100.0/24
                                │
                     ┌──────────▼──────────┐
                     │   Server VM         │
                     │  192.168.100.2      │
                     │  192.168.0.10       │
                     │  eth0: vigilant     │
                     │  eth1: Database     │
                     │  (Flask Backend)    |
                     │  PORT 5000          |
                     └──────────┬──────────┘
                                │
                                | HTTPS (mTLS)
                                │ PostgreSQL SSL
                                │ Internal Network
                                │ Port 5432
                                │
                     ┌──────────▼──────────┐
                     │   Database VM       │
                     │  192.168.0.100      │
                     │  eth0: Internal only│
                     │  (PostgreSQL 17)    │
                     └─────────────────────┘

Network Segments:
  - Client Network: 192.168.200.0/24 (Client ↔ vigilant)
  - vigilant-Server Network: 192.168.100.0/24 (vigilant ↔ Server)
  - Database Network: 192.168.0.0/24 (Server ↔ Database)
```

**Machine Specifications:**

1. **Database VM (192.168.0.100)**
   - *OS:* Ubuntu/Debian Linux
   - *Technology:* PostgreSQL 17
   - *Rationale:* JSONB support for flexible document storage, SSL/TLS native support, ACID guarantees
   - *Network:* Internal interface (eth0) only - 192.168.0.0/24
   - *Firewall:* Allow incoming 5432/tcp from 192.168.100.2 only, DROP all other
   - *TLS Config:* `ssl=on`, client certificate required (`hostssl` with `cert` method)
   - *Data:* Stores `users` and `documents` tables
   - *Certificates:* `db.pem` (server cert), `db.key` (private key), `ca.pem` (CA root)

2. **Application Server VM (192.168.100.2 / 192.168.0.10)**
   - *OS:* Ubuntu/Debian Linux
   - *Technology:* Flask 3.0 + Python 3.11 + Gunicorn
   - *Rationale:* Backend processing, document encryption/decryption, database operations
   - *Network:* 
     - `eth0` (vigilant): 192.168.100.2/24 for API gateway access
     - `eth1` (database): 192.168.0.10/24 for database access
   - *Ports:* 5000 (HTTPS with mTLS)
   - *Firewall:* Allow incoming 5000/tcp from 192.168.100.1, allow outgoing 5432/tcp to 192.168.0.100
   - *TLS Config:* SSL context with `CERT_REQUIRED`, verifies vigilant certificate
   - *Endpoints:* POST /api/document/submit, GET /api/document/list, GET /api/document/get
   - *Certificates:* `server.pem` (server cert), `server.key` (private key), `ca.pem` (CA root), `app_worker.pem` + `app_worker.key` (DB client certs)

3. **vigilant VM (192.168.100.1 / 192.168.200.1) - API Gateway**
   - *OS:* Ubuntu/Debian Linux
   - *Technology:* Flask 3.0 + Python 3.11 (Reverse Proxy/API Gateway)
   - *Rationale:* Security isolation layer, request validation, rate limiting, client authentication
   - *Network:*
     - `eth0` (clients): 192.168.200.1/24 for client connections
     - `eth1` (server): 192.168.100.1/24 for backend server access
   - *Ports:* 6000 (HTTPS with mTLS on client-facing interface)
   - *Firewall:* Allow incoming 6000/tcp on eth0 from 192.168.200.0/24, allow outgoing 5000/tcp on eth1 to 192.168.100.2
   - *TLS Config:* Dual SSL contexts - client-facing (verifies peer certs), server-facing (presents vigilant cert)
   - *Functions:* Request forwarding, authentication, logging, certificate validation
   - *Certificates:* `vigilant.pem` (server cert for clients), `vigilant.key` (private key), `vigilant_client.pem` + `vigilant_client.key` (client cert for server), `ca.pem` (CA root)

4. **Client VMs (192.168.200.2, 192.168.200.3, etc.)**
   - *OS:* Ubuntu/Debian Linux
   - *Technology:* Python 3.11 CLI client
   - *Network:* Internal interface (eth0) - 192.168.200.0/24 to access vigilant
   - *Firewall:* Allow outgoing 6000/tcp to 192.168.200.1, allow ICMP for ping, DROP all incoming
   - *Authentication:* Client certificates for mTLS with vigilant
   - *Certificates:* `peer{N}.pem` (client cert), `peer{N}.key` (private key), `ca.pem` (CA root to verify vigilant)
   - *Keys:* RSA keypair for signing documents (stored locally)

**Technology Justification:**
- **Virtual Machines:** True network isolation, realistic deployment scenario, production-like environment
- **PostgreSQL 17:** Latest stable, native SSL/TLS, excellent JSONB performance
- **Flask + Gunicorn:** Production-ready WSGI server, handles concurrent connections
- **Python cryptography:** Industry-standard library, FIPS 140-2 compliance, constant-time operations
- **OpenSSL:** Battle-tested TLS implementation, certificate management tools

#### 2.2.2. Server Communication Security

To secure communications, the system uses strong TLS with mutual authentication where appropriate. The three logical channels are described below along with practical deployment guidance.

##### 1. Client ↔ Vigilant (mTLS 1.2+ with Server Verification)
 
* **Approach:** The Vigilant Gateway (vigilant.py) terminates TLS on the client-facing interface (eth1: 192.168.200.1) at port 6000.
* **Certificates:** The Vigilant presents its server certificate (vigilant.pem) to the client. The client identifies itself by presenting its own infrastructure certificate and private key (client.pem and client.key).
* **Verification:** 
    * **Server-Side:** The Vigilant is configured with ssl.CERT_REQUIRED, meaning it strictly enforces and verifies the client's certificate against the internal CA (ca.pem) during the handshake. After the secure connection is established, the gateway further identifies the specific peer by verifying the RSA-PSS signature attached to the encrypted_payload in the request.

    * **Client-Side:** The main.py client uses an SSLContext configured with the ca.pem to verify the Vigilant’s identity and provides its local client certificate and key to complete the mutual authentication.
* **Notes:** Requests from unauthorized or unknown signers are blocked at the gateway before being proxied to the internal network.

##### 2. Vigilant ↔ Server (Internal mTLS)
* **Approach:** The Vigilant gateway acts as a secure proxy, forwarding validated traffic from `eth0` to the internal Application Server (`192.168.100.2:6000`).
* **Certificates:** 
    * **Vigilant:** Presents a client certificate (`vigilant.pem`) to the Server.
    * **Server:** Presents its own server certificate (`server.pem`).
* **Verification:** * The Flask Server is configured with an `ssl_context` and requires a CA certificate (`SIRS_TLS_CA`) to verify the Vigilant’s client certificate.
    * This **mTLS** setup ensures the Server only accepts traffic originating from the authenticated Vigilant instance.
* **Notes:** All communication occurs over a dedicated internal subnet (`192.168.100.0/24`) inaccessible to clients.

##### 3. Server ↔ Database (PostgreSQL mTLS)
* **Approach:** The Application Server connects to the PostgreSQL VM using `psycopg2` with strict SSL enforcement.
* **Configuration (DB):** The database is configured for `hostssl` access, requiring valid certificates.
* **Configuration (Server Client):**
    * **`sslmode='verify-full'`**: The server verifies the database's certificate and hostname to prevent MITM.
    * **mTLS Parameters**: The server presents its specific DB client certificate (`db_client.pem`) and key (`db_client.key`) to authenticate as the `app_worker` user.
**Notes:** The use of `verify-full` ensures that the connection is only established if the DB certificate's Subject Alternative Name (SAN) matches the `DB_HOST` IP.


**Firewalls:**

Each node implements a **Default DROP** policy, only allowing traffic that matches specific cryptographic and service requirements.

| Node | Interface/IP | Purpose | Policy Detail |
| :--- | :--- | :--- | :--- |
| **Peer (Client)** | `eth0` | Gateway Access | **DROP** all input; accepts established traffic from Vigilant (`192.168.200.1`). |
| **Vigilant** | `eth1` (192.168.200.1) | Public Entry | Accepts TCP/6000 from the Peer network for HTTPS traffic. |
| **Vigilant** | `eth0` (192.168.100.1) | Internal Backhaul | Routes filtered traffic to the Server at `192.168.100.2:5000`. |
| **Server** | `eth1` (192.168.100.2) | vigilant Link | Accepts traffic **only** from the Vigilant (`192.168.100.1`) on TCP/5000. |
| **Server** | `eth0` (192.168.0.10) | Database Link | Connects to the Database at `192.168.0.100:5432`. |
| **Database** | `eth0` (192.168.0.100) | Secure Storage | Only accepts TCP/5432 from the Application Server (`192.168.0.10`). |

**Key Distribution Strategy:**

The security of the communication channels relies on a centralized **Internal Root CA** and per-component certificates managed via the `generate_test_certs.sh` script.

**1. Infrastructure Identity (mTLS Certificates):**
* **CA Root**: A 4096-bit RSA CA is generated (`ca.pem`) and distributed to all VMs to enable mutual verification of all infrastructure components.
* **Vigilant Gateway**: Operates with its own server certificate (`vigilant.pem/key`) for HTTPS communication with peers and as a client for internal forwarding.
* **Peer Clients**: Each registered user holds a unique certificate and private key (e.g., client.pem/key) used to perform mTLS authentication with the Vigilant gateway.
* **Application Server**: Holds multiple credentials for its dual roles:
    * **Server Identity**: `server.pem/key` to authenticate itself to the Vigilant gateway.
    * **Database Client**: `db_client.pem/key` used for **mTLS** authentication to the PostgreSQL database as the `app_worker` user.
* **PostgreSQL Database**: Uses a dedicated server certificate (`db.pem/key`) to identify itself to the application server during the SSL handshake.
* **Security Enforcement**: All certificates include **Subject Alternative Names (SANs)** covering relevant internal IPs and DNS names (e.g., `IP:192.168.100.2`, `DNS:deathnode-db`) to ensure strict validation. All private keys are restricted with `chmod 600`.

**2. User Identity & Key Generation:**
* **Peer Keys**: The script generates unique 4096-bit RSA private keys for each peer (e.g., `sirs_project/shared/test_secrets/peer1/client.key` then client copies manually to `client/certs/peer1` ).
* **Public Key Registration**: Peer public keys are automatically extracted from private keys and injected into the database's `seed.sql` file. This allows the Vigilant and Server to verify **RSA-PSS signatures** at the application layer.

**Challenges Encountered:**

**Challenge 1: Certificate SANs (Subject Alternative Names)**
- **Issue**: Standard certificates often fail validation if the client connects via IP rather than a hostname.
- **Solution**: The `generate_test_certs.sh` script automatically populates SAN extensions with defined IP variables for every component certificate.

**Challenge 2: Secure Database mTLS**
- **Issue**: Default database connections are vulnerable to Man-in-the-Middle (MITM) attacks.
- **Solution**: The script generates a dedicated `db_client.pem` for the server, allowing PostgreSQL to perform **mutual authentication** while the server uses `sslmode=verify-full`.

### 2.3. Security Challenge: vigilant - Malicious User Detection and Mitigation

#### 2.3.1. Challenge Overview

The security challenge addresses a critical vulnerability in anonymous reporting systems: **malicious registered users** abusing the service by submitting fabricated reports, impersonating other users, or flooding the system with high-volume uploads that degrade availability. While the base design provided confidentiality (encryption), authenticity (signatures) and integrity (hash chains), it lacked an **enforcement layer** capable of detecting and mitigating abuse from authenticated peers who possess valid signing keys.

**Key Attack Vectors Addressed:**
1. **Spam/Flooding:** Valid users submitting excessive documents to exhaust server resources or pollute the dataset
2. **Impersonation:** Attackers signing documents with their own key but claiming another user's `reporter_pseudonym` in metadata
3. **Replay Attacks:** Resubmitting previously captured valid payloads to bypass rate limits or cause duplicate processing
4. **Unverifiable Signatures:** Attackers attempting to submit documents with invalid or unknown signatures

**Solution Approach:**
- Introduced a **vigilant Gateway (vigilant)** - a security enforcement layer positioned between clients (192.168.200.0/24) and the backend Server (192.168.100.2)
- Implements **application-layer validation** beyond transport-layer TLS: verifies payload signatures, detects impersonation, tracks nonces, and enforces rate limits
- Uses **in-memory state stores** for sub-millisecond enforcement decisions (bans, upload counters, nonce tracking) without database round-trips
- **Trust boundary shift:** The vigilant validates signatures and enforces policy but deliberately does **not** hold document encryption keys—it cannot decrypt report contents, preserving confidentiality even if the gateway is compromised

#### 2.3.2. Attacker Model

**Trust Tiers:**

**Fully Trusted: None (Mathematical Zero-Trust)**
* **Rationale**: The system is designed so that no single component has a complete view of all security properties. 
* **Basis**: Infrastructure components (Vigilant, Server) possess the network identity keys (TLS) but lack the data keys (Shared Secret). Conversely, Peers possess the data keys but are considered untrusted originators of data.

**Partially Trusted: Infrastructure (Vigilant, Server, Database)**
* **Basis**: These components are trusted exclusively for **Availability** and **Access Control**.
* **Vigilant Gateway**: Trusted to enforce firewall rules, verify RSA-PSS signatures for authentication, and manage rate-limiting/bans.
* **Backend Server**: Trusted to synchronize document IDs and manage concurrent uploads via the `upload_lock`.
* **Constraint**: Because the infrastructure cannot decrypt the ciphertext, it is "blind" to the internal integrity of the reports. It cannot verify if the `chain_hash` is calculated correctly or if the JSON content is well-formed.

**Untrusted: Registered Client Peers (192.168.200.x)**
* **Basis**: Peers are the primary threat vector for **Logical Corruption**.
* **Risk**: A malicious or buggy peer can submit a document that is cryptographically valid (signed correctly) but logically broken (invalid `chain_hash` or corrupt JSON).
* **Verification Gap**: The infrastructure will blindly store these payloads because the outer signature is valid. Detection only occurs when *other* peers decrypt and audit the chain.

**Attacker Capabilities:**
1. **Valid Credentials:** Possess a valid client certificate signed by the system CA and corresponding private key (i.e., a registered peer with transport-layer authentication)
2. **Signature Generation:** Can generate valid RSA-PSS signatures over arbitrary payloads using their own private signing key
3. **Observe Network Behavior:** Can observe their own request/response timing and HTTP status codes to infer system state

**Attacker Limitations:**
- **Cryptographic Hardness:** Cannot break AES-256-GCM, RSA-PSS with 2048+ bit keys, or HKDF under standard computational assumptions
- **Key Compromise:** Cannot forge signatures for other users' private keys without physical/logical compromise of those keys
- **Network Isolation:** Cannot directly access the Backend Server or Database due to network segmentation enforced by firewall rules and mTLS authentication requirements
- **No Encryption Keys:** Cannot derive document encryption keys (generated via HKDF from out-of-band shared secrets) without access to those secrets
- **Nonce Tracking:** Cannot reuse GCM nonces without detection by vigilant's `seen_nonces` tracking (replay prevention)
- **Rate Limiting:** Cannot bypass per-user upload quotas enforced by vigilant (spam prevention)
- **Signature Binding:** Cannot successfully impersonate other users because signature verification against claimed pseudonym will fail (impersonation detection)
- **Transport Security:** Cannot eavesdrop on TLS-protected traffic without breaking TLS 1.2+ with forward secrecy

**Attack Scenarios Defended:**

| Attack Type | Detection Method | Mitigation Response | Duration |
|-------------|------------------|---------------------|----------|
| **Spam/Flooding** | Rate limiting: >2 uploads per 60s window tracked in `user_uploads` dict | Ban username + source IP | 30 min (configurable via env) |
| **Impersonation** | Signature verification fails for claimed pseudonym but succeeds for different user in `users_cache` | Ban actual signer + source IP | 60 min + IP escalation tracking |
| **Replay Attack** | Duplicate GCM nonce detected in `seen_nonces` dict (SHA-256 hex index) | Immediate IP ban | 60 min |
| **Unverifiable Signature** | Signature does not match **any** public key in `users_cache` | Track IP failure count; ban after threshold | 120 min (after 5 attempts in 5 min window) |
| **Banned User Retry** | Username found in `banned_users` dict with non-expired timestamp | Reject with 403 + ban expiry timestamp | Original ban duration |
| **Banned IP Retry** | Source IP found in `banned_ips` dict with non-expired timestamp | Reject with 403 + ban expiry info | Original ban duration |

#### 2.3.3. Solution Design and Implementation

**Architecture Overview:**

The **vigilant Gateway** (`vigilant/src/vigilant.py`) is a Flask-based security enforcement layer that acts as a **reverse proxy with application-layer validation**. It sits at the network boundary between untrusted clients (DMZ: 192.168.200.0/24) and the trusted internal backend (192.168.100.0/24), performing deep inspection and policy enforcement before forwarding validated requests over mTLS.

**Network Positioning:**
```
Client (192.168.200.x)  →  vigilant eth1 (192.168.200.1:6000)  →  [Validation Layer]
                                                                  ↓
vigilant eth0 (192.168.100.1)  →  Server (192.168.100.2:5000)  →  Database (192.168.0.100:5432)
```

**In-Memory State Stores (for low-latency enforcement):**

| Data Structure | Type | Purpose | TTL/Cleanup |
|----------------|------|---------|-------------|
| `users_cache` | `{username: public_key_pem}` | Public keys loaded from Server at startup via `GET /users` over mTLS | Loaded once; could add periodic refresh |
| `banned_users` | `{username: expiry_datetime\|None}` | Temporary/permanent user bans; None = permanent | Lazy expiry check on access; periodic cleanup in health check |
| `banned_ips` | `{ip: expiry_datetime\|None}` | IP-level bans for repeat offenders | Same as `banned_users` |
| `user_uploads` | `{username: [timestamp, ...]}` | Sliding window of upload timestamps for rate limiting | Sliding window: timestamps outside 60s window removed before check |
| `seen_nonces` | `{nonce_hex: timestamp}` | SHA-256 hex of GCM nonces to prevent replay attacks | Periodic cleanup every ~50 requests; removes nonces >60min old |
| `ip_failed_attempts` | `{ip: [(timestamp, reason), ...]}` | Failed auth/impersonation attempts to trigger IP bans | Sliding window: entries outside `IP_BAN_WINDOW` (default 5 min) removed |

**Configuration (Environment Variables):**

- `DEATHNODE_SERVER_URL` - Backend server URL (default: `https://192.168.100.2:5000`)
- `CA_CERT` - Path to CA certificate for verifying backend Server TLS
- `vigilant_CLIENT_CERT` / `vigilant_CLIENT_KEY` - mTLS client cert for authenticating to Server
- `VIGILANT_TLS_CERT` / `VIGILANT_TLS_KEY` - TLS server cert for accepting client connections on eth1
- `ENABLE_IP_BANS` - Toggle IP-based banning (default: `"1"` = enabled)
- `IP_BAN_THRESHOLD` - Failed attempts before IP ban (default: `5`)
- `IP_BAN_WINDOW` - Time window for counting failures (default: `300` seconds)

**Request Validation Pipeline (`POST /documents`):**

The vigilant performs an **8-step validation** before forwarding any upload request:

**Step 0: IP Ban Check**
- Check if `request.remote_addr` exists in `banned_ips` with non-expired timestamp
- **Action if banned:** Return `403 Forbidden` with ban expiry info; log event

**Step 1: Replay Detection (Early Check)**
```python
nonce_hex = base64.b64decode(encrypted_payload['nonce']).hex()
if nonce_hex in seen_nonces:
    ban_ip(client_ip, duration_minutes=60, reason="Replay attack")
    return 403
```
- **Rationale:** Prevents expensive signature verification on replayed payloads
- **Side Effect:** Immediate 60-minute IP ban on replay attempt

**Step 2: Metadata Validation**
- Verify presence of `encrypted_payload`, `payload_signature`, and `metadata.reporter_pseudonym`
- **Action if missing:** Return `400 Bad Request`

**Step 3: Signer Identification**
```python
def find_signer_username(data):
    for username, public_key_pem in users_cache.items():
        if verify_payload_signature(data, public_key_pem):
            return username
    return None
```
- Iterate through all cached public keys to find which user actually signed the payload
- **Cost:** O(n) signature verifications where n = number of registered users (acceptable for small-to-medium deployments; could optimize with key fingerprints)

**Step 4: Ban Status Check (Actual Signer)**
- If `actual_signer` identified and exists in `banned_users` with non-expired ban → reject `403`
- **Note:** Checks the **signer**, not the claimed pseudonym (prevents ban evasion via pseudonym changes)

**Step 5: Impersonation Detection**
```python
public_key_claimed = get_user_public_key(reporter_pseudonym)  # claimed user
if not verify_payload_signature(data, public_key_claimed):
    if actual_signer and actual_signer != reporter_pseudonym:
        # IMPERSONATION: signed by user X but claimed user Y
        ban_user(actual_signer, duration_minutes=60)
        if record_ip_failure(client_ip, "impersonation"):
            ban_ip(client_ip, duration_minutes=60)
        return 403
```
- **Attack:** User Alice signs a document but claims `reporter_pseudonym: "Bob"` in metadata
- **Detection:** Signature verifies against Alice's key but not Bob's key
- **Response:** Ban Alice (the actual signer) for 60 minutes; track IP failure and ban IP if threshold exceeded

**Step 6: Spam/Rate Limiting**
```python
def is_spam(username, threshold=2, window_seconds=60):
    user_uploads[username] = [ts for ts in user_uploads[username] 
                               if (now - ts).total_seconds() < window_seconds]
    if len(user_uploads[username]) >= threshold:
        return True
    user_uploads[username].append(now)
    return False
```
- **Threshold:** 2 uploads per 60 seconds (configurable in function signature)
- **Action if exceeded:** Ban user + IP for 30 minutes; return `429 Too Many Requests`

**Step 7: Record Nonce**
```python
seen_nonces[nonce_hex] = datetime.now()
# Cleanup runs every ~50 requests
if len(seen_nonces) % 50 == 0:
    cleanup_old_nonces(max_age_minutes=60)
```
- Prevents future replay attempts of this specific payload
- Periodic cleanup prevents unbounded memory growth

**Step 8: Forward to Backend**
```python
response = session.post(
    f"{DEATHNODE_SERVER_URL}/documents",
    json=data,
    verify=CA_CERT,  # Verify Server's TLS cert
    cert=(vigilant_CLIENT_CERT, vigilant_CLIENT_KEY),  # mTLS client auth
    timeout=30
)
return response.json(), response.status_code
```
- Only reached if all validation checks pass
- Uses mTLS to authenticate vigilant to Server (Server requires valid client cert)
- Relays Server response back to client unchanged

**Ban Policies and Tuning:**

| Violation Type | User Ban | IP Ban | Escalation | Notes |
|----------------|----------|--------|------------|-------|
| Spam (>2 uploads/60s) | 30 min | 30 min | N/A | Both banned immediately |
| Impersonation | 60 min (actual signer) | 60 min (if >threshold) | IP tracked in `ip_failed_attempts` | Escalates to IP ban after `IP_BAN_THRESHOLD` attempts |
| Replay Attack | N/A | 60 min | Immediate | No user ban (may not identify signer) |
| Unverifiable Signature | N/A | 120 min (after threshold) | Tracked per IP | 5 failures in 5 min window → IP ban |
| Banned User Retry | No change | N/A | N/A | Rejects but doesn't extend ban |

**Security Guarantees:**

1. **Defense in Depth:** TLS authenticates transport identity; application-layer checks validate cryptographic signatures and enforce usage policy
2. **No Content Access:** vigilant validates signatures over `payload_hash = SHA256(metadata || nonce || ciphertext)` but never holds document decryption keys—cannot read plaintext reports
3. **Impersonation Prevention:** Signature must match claimed `reporter_pseudonym` or actual signer is identified and banned
4. **Replay Immunity:** Each GCM nonce accepted exactly once; duplicates trigger immediate IP ban
5. **Sybil Resistance (partial):** IP-level bans slow down attackers with multiple accounts but same source IP; determined attackers with many IPs require additional countermeasures 

**Limitations and Future Work:**

- **Content Validation:** Vigilant cannot detect semantically false/fabricated reports (requires human review or ML-based content analysis)
- **Distributed State:** Current in-memory design doesn't scale horizontally; Memcached backend needed for multi-instance deployments
- **IP Ban Evasion:** Determined attackers with botnets can rotate IPs faster than bans accumulate; need adaptive rate limiting or CAPTCHA challenges
- **Denial of Service:** Expensive signature verification in `find_signer_username()` is O(n) per request; could be abused to cause CPU exhaustion

**Sequence Diagram - Document Submission Flow:**

```
┌──────┐          ┌───────────┐          ┌────────┐           ┌──────────┐
│Client│          │ vigilant  │          │ Server │           │ Database │
└──┬───┘          └─────┬─────┘          └───┬────┘           └────┬─────┘
   │                    │                    │                     │
   │ POST /documents    │                    │                     │
   │ {encrypted_payload,│                    │                     │
   │  payload_signature,│                    │                     │
   │  metadata}         │                    │                     │
   │───────────────────>│                    │                     │
   │                    │                    │                     │
   │                    │ [0. Check IP ban]  │                     │
   │                    │ if banned → 403    │                     │
   │                    │                    │                     │
   │                    │ [1. Check replay]  │                     │
   │                    │ if nonce in seen_nonces:                 │
   │                    │   ban_ip(60min) → 403                    │
   │                    │                    │                     │
   │                    │ [2. Validate metadata]                   │
   │                    │ if missing fields → 400                  │
   │                    │                    │                     │
   │                    │ [3. Identify signer]                     │
   │                    │ for each user in users_cache:            │
   │                    │   verify_signature() → actual_signer     │
   │                    │                    │                     │
   │                    │ [4. Check signer ban]                    │
   │                    │ if actual_signer banned → 403            │
   │                    │                    │                     │
   │                    │ [5. Impersonation check]                 │
   │                    │ if signature ≠ claimed_pseudonym:        │
   │                    │   ban_user(60min)                        │
   │                    │   ban_ip(60min) → 403                    │
   │                    │                    │                     │
   │                    │ [6. Rate limit check]                    │
   │                    │ if >2 uploads/60s:                       │
   │                    │   ban_user(30min)                        │
   │                    │   ban_ip(30min) → 429                    │
   │                    │                    │                     │
   │                    │ [7. Record nonce]  │                     │
   │                    │ seen_nonces[nonce] = now                 │
   │                    │                    │                     │
   │                    │ [8. Forward validated request]           │
   │                    │ POST /documents    │                     │
   │                    │ (mTLS client auth) │                     │
   │                    │───────────────────>│                     │
   │                    │                    │                     │
   │                    │                    │ [Verify chain_hash]  │
   │                    │                    │                     │
   │                    │                    │ INSERT document     │
   │                    │                    │ (SSL/mTLS)          │
   │                    │                    │────────────────────>│
   │                    │                    │                     │
   │                    │                    │ {id, row_count}     │
   │                    │                    │<────────────────────│
   │                    │                    │                     │
   │                    │ 201 {document_id}  │                     │
   │                    │<───────────────────│                     │
   │                    │                    │                     │
   │ 201 {document_id}  │                    │                     │
   │<───────────────────│                    │                     │
   │                    │                    │                     │
```


## 3. Conclusion

**Main Achievements:**

1. **Secure Document Format:** Implemented custom cryptographic library with AES-256-GCM encryption, RSA-PSS signatures, HKDF key derivation, and cumulative hash chain verification for tamper-proof document history
2. **Multi-VM Infrastructure:** Deployed 4-VM architecture with three-tier network segmentation (Client network 192.168.200.0/24, Internal network 192.168.100.0/24, Database network 192.168.0.0/24) enforced by firewall rules and isolated interfaces
3. **vigilant Security Gateway:** Built application-layer security enforcement with signature verification, impersonation detection, replay prevention via nonce tracking, and rate limiting to defend against spam and abuse from authenticated users
4. **End-to-End Encryption:** Achieved zero-trust confidentiality model where only clients possess shared secrets to decrypt report plaintext; all infrastructure (vigilant, Server, Database) operates on opaque ciphertexts
5. **TLS Throughout:** Configured Flask in-process TLS for client-facing and internal communications, PostgreSQL SSL/mTLS for database connections, with certificate-based authentication across all layers

**Requirements Status:**

| Requirement | Status | Justification |
|-------------|--------|---------------|
| **SR1** - Confidentiality     | Satisfied | AES-256-GCM with HKDF-derived keys from out-of-band shared secrets. Infrastructure cannot decrypt payloads. |
| **SR2** - Authenticity        | Satisfied | RSA-PSS signatures validated by vigilant before forwarding. Impersonation attempts detected and banned. |
| **SR3** - Integrity           | Satisfied | Cumulative hash chains with `chain_hash = SHA256(prev_chain_hash || document)`. Tampering breaks all subsequent hashes. |
| **SR4** - Protection | Satisfied | End-to-end encryption. Server stores only ciphertexts. Even with server compromise, plaintext remains protected. |
| **Step 3** - Infrastructure | Satisfied | 4-VM deployment (Database + Server + vigilant + 2 Clients) with three isolated network segments and iptables firewall rules. |
| **Step 4** - TLS/SSL | Satisfied | TLS 1.2+ on all channels: Client↔vigilant (server-side TLS), vigilant↔Server (mTLS with client certs), Server↔Database (PostgreSQL SSL with optional mTLS). |
| **Security Challenge** | Satisfied | vigilant Gateway with 8-step validation pipeline: IP ban check, replay detection, signer identification, impersonation detection, spam rate limiting, signature verification. In-memory ban management with configurable policies. |
| **Network Isolation** | Satisfied | Three isolated networks with dedicated firewall scripts per VM. Clients blocked from directly accessing Server/Database. Defense-in-depth with vigilant as single point of entry. |

**Possible Future Enhancements:**

1. **Persistent Ban Storage:** Replace in-memory ban dictionaries with Redis or database-backed storage to enable distributed vigilant deployments and survive restarts
2. **Optimized Signer Identification:** Current O(n) signature verification in `find_signer_username()` could be optimized with key fingerprints or requiring client cert CommonName to match claimed pseudonym
3. **Monitoring and Alerting:** Add logging aggregation, metrics collection, and real-time alerts for security events (impersonation attempts, IP bans, unusual traffic patterns)

**Concluding Statement:**

The DeathNode project successfully demonstrates that secure anonymous reporting systems can be built using modern cryptographic primitives and defense-in-depth architecture. By combining client-side encryption (confidentiality), digital signatures (authenticity), hash chains (integrity), and a multi-layered VM infrastructure with an enforcement gateway (availability protection), we achieved a system where no single component is fully trusted yet the overall system provides strong security guarantees.

The key insight from this project is the **zero-trust confidentiality model**: only clients possess the shared secrets needed to decrypt report contents, meaning that even complete compromise of the vigilant, Server, or Database VMs does not expose plaintext data. This design choice creates an inherent limitation—infrastructure cannot verify encrypted payload correctness (e.g., chain_hash validity)—but it maximizes confidentiality in untrusted environments.

The vigilant Gateway proved essential for defending against application-layer attacks that transport-layer TLS cannot prevent: authenticated users abusing valid credentials to spam, impersonate, or replay attacks. The 8-step validation pipeline with in-memory state tracking (nonce history, upload counters, ban lists) provides sub-millisecond enforcement decisions without database round-trips, demonstrating that security and performance can coexist with careful design.

Technical challenges included certificate management across three network segments, configuring Flask in-process TLS correctly, implementing PostgreSQL SSL/mTLS with psycopg2, designing the signature-to-pseudonym binding for impersonation detection, and balancing false-positive rates in IP-based bans (legitimate users behind NAT vs. attackers). These challenges reinforced the importance of testing each layer independently before integration and maintaining detailed documentation for complex multi-VM deployments.

This project provided invaluable hands-on experience with production-grade security engineering: from selecting appropriate cryptographic primitives (AES-GCM vs CBC, RSA-PSS vs PKCS#1 v1.5) to architecting network segmentation with defense-in-depth principles to implementing stateful security enforcement at the application layer. The skills and insights gained—particularly around trust boundaries, threat modeling with zero-trust assumptions, and operational security for distributed systems—will directly inform our approach to future projects involving sensitive data and adversarial environments.

## 4. Bibliography

1. **Python Cryptography Library Documentation**  
   Python Cryptographic Authority, *Cryptography - Cryptographic Recipes and Primitives for Python Developers*, Read the Docs, 2024.  
   https://cryptography.io/en/latest/

2. **NIST Special Publication 800-38D**  
   Dworkin, M., *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*, National Institute of Standards and Technology, 2007.  
   https://doi.org/10.6028/NIST.SP.800-38D

3. **RFC 8017 - PKCS #1: RSA Cryptography Specifications**  
   Moriarty, K., Kaliski, B., Jonsson, J., Rusch, A., *PKCS #1: RSA Cryptography Specifications Version 2.2*, IETF, 2016.  
   https://datatracker.ietf.org/doc/html/rfc8017

4. **RFC 5280 - Internet X.509 Public Key Infrastructure Certificate**  
   Cooper, D., et al., *Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile*, IETF, 2008.  
   https://datatracker.ietf.org/doc/html/rfc5280

5. **RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)**  
   Krawczyk, H., Eronen, P., *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*, IETF, 2010.  
   https://datatracker.ietf.org/doc/html/rfc5869

6. **TLS/SSL Protocol**  
   Dierks, T., Rescorla, E., *The Transport Layer Security (TLS) Protocol Version 1.2*, IETF RFC 5246, 2008.  
   https://datatracker.ietf.org/doc/html/rfc5246

7. **iptables Firewall Documentation**  
   Netfilter Core Team, *iptables - Administration tool for IPv4 packet filtering and NAT*, Linux man pages, 2024.  
   https://linux.die.net/man/8/iptables

8. **PostgreSQL Documentation**  
   PostgreSQL Global Development Group, *PostgreSQL 15 Documentation - Secure TCP/IP Connections with SSL*, PostgreSQL, 2024.  
   https://www.postgresql.org/docs/15/ssl-tcp.html

9. **Flask Documentation**  
   Pallets Projects, *Flask Documentation (3.0.x)*, Flask, 2024.  
   https://flask.palletsprojects.com/

10. **OpenSSL Documentation**  
    OpenSSL Software Foundation, *OpenSSL Command Line Utilities*, OpenSSL Docs, 2024.  
    https://www.openssl.org/docs/

11. **TLS/SSL Best Practices**  
    Mozilla, *Security/Server Side TLS*, Mozilla Wiki, 2024.  
    https://wiki.mozilla.org/Security/Server_Side_TLS

12. **OWASP Cryptographic Storage Cheat Sheet**  
    OWASP Foundation, *Cryptographic Storage Cheat Sheet*, OWASP, 2024.  
    https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

----
END OF REPORT
