# A10 DeathNode

## Team

| Number  | Name             | User                                 | E-mail                                               |
| --------|------------------|--------------------------------------|------------------------------------------------------|
| 106930  | André Bento      | <https://github.com/ElPollero>       | <andre.bento@tecnico.ulisboa.pt>                     |
| 107059  | Pedro Loureiro   | <https://github.com/PedroLoureiro1>  | <pedro.d.loureiro@tecnico.ulisboa.pt>                |
| 107365  | João Santos      | <https://github.com/joao-sntos>      | <joao.miguel.ferreira.dos.santos@tecnico.ulisboa.pt> |


![André Bento](img/Andre.png) ![Pedro Loureiro](img/Pedro.png) ![João Santos](img/Joao.png)

## Contents

This repository contains documentation and source code for the *Network and Computer Security (SIRS)* project.

The [REPORT](REPORT.md) document provides a detailed overview of the key technical decisions and various components of the implemented project.
It offers insights into the rationale behind these choices, the project's architecture, and the impact of these decisions on the overall functionality and performance of the system.

This document presents installation and demonstration instructions.

**Project:** DeathNode - Secure Anonymous Reporting System  
**Technology:** Python 3.11, PostgreSQL, Flask, Virtual Machines  
**Security Features:** Symmetric encryption with shared secrets, digital signatures, hash chains, mTLS authentication

## Installation

**Project Assumptions:**

- **Fixed Network:** We assume the network is static, meaning only the pre-configured Virtual Machines can participate and no new users can join after the system is running.

- **Secrets Already Shared:** Every user is assumed to already have the "shared secret" needed to encrypt and decrypt reports before they start using the system.

- **Keys and Certificates Ready:** All security certificates and cryptographic keys are generated and distributed to the machines before the project starts.

- **Database Pre-filled:** We assume all user accounts and their public keys are already stored in the database so the system can recognize them immediately.


To see the project in action, it is necessary to setup three separate Virtual Machines with network isolation.

The following diagram shows the VM topology:

```
                     ┌─────────────────────┐
                     │   Client VM         │
                     │  192.168.200.2      │
                     └──────────┬──────────┘
                                │
                                │ HTTPS (TLS)
                                │ 192.168.200.0/24
                                │
                     ┌──────────▼──────────┐
                     │  Vigilant  VM (API) │
                     │  192.168.200.1      │
                     │  192.168.100.1      │
                     │  (Flask Proxy)      │
                     └──────────┬──────────┘
                                │
                                │ HTTPS (mTLS)
                                │ 192.168.100.0/24
                                │
                     ┌──────────▼──────────┐
                     │   Server VM         │
                     │  192.168.100.2      │
                     │  192.168.0.10       │
                     │  (Flask Backend)    │
                     └──────────┬──────────┘
                                │
                                | HTTPS (mTLS)
                                │ PostgreSQL SSL
                                │ 192.168.0.0/24
                                │
                     ┌──────────▼──────────┐
                     │   Database VM       │
                     │  192.168.0.100      │
                     │  (PostgreSQL 17)    │
                     └─────────────────────┘
```

### Prerequisites

**System Requirements:**
- 4 Virtual Machines (VM software like VirtualBox, VMware, or cloud VMs)
- Each VM: Ubuntu 22.04 LTS or similar Linux distribution
- Python 3.11+ on all VMs
- PostgreSQL 17 on Database VM
- OpenSSL for certificate generation
- Git for cloning repository

**Network Setup:**
- Client Network: 192.168.200.0/24 (Client ↔ Vigilant)
- Vigilant-Server Network: 192.168.100.0/24 (Vigilant ↔ Server)
- Database Network: 192.168.0.0/24 (Server ↔ Database)
- All networks are internal with firewall rules (iptables) configured on each VM

### Setup Instructions

#### Overview

The system is architected with three isolated network segments to enforce defense-in-depth security. Each network segment serves a specific purpose and only allows necessary communication between adjacent layers:

**network (server-db) 192.168.0.0/24** - Internal Database Network
- This is the most protected network segment, containing only the PostgreSQL database and the server's internal interface
- The database (192.168.0.100) is completely isolated from external networks and only accepts connections from the server
- Communication uses PostgreSQL SSL with mutual TLS (mTLS) for authentication

```
db eth0 192.168.0.100
server eth0 192.168.0.10
```

**network (vigilant-server) 192.168.100.0/24** - Application Network
- This middle tier connects the server to the vigilant/Vigilant component
- The server (192.168.100.2) exposes its Flask API only to the vigilant
- The vigilant (192.168.100.1) acts as a monitoring proxy and validation layer
- All communication uses HTTPS with mTLS authentication

```
server eth1 192.168.100.2
vigilant eth0 192.168.100.1
```

**network (peers-vigilant) 192.168.200.0/24** - Client Network

```
vigilant eth1 192.168.200.1
client eth0 192.168.200.0/24
```

This three-tier architecture ensures that clients cannot directly access the backend server or database, and the database is completely isolated from any external network. The vigilant acts as a security gateway, monitoring and validating all traffic between clients and the server.

#### how to setup the vms

- **DB**: attach 1 ethernet adapter to the internal network `server-db` (Int Net 1) and run:

```bash
# Delete all existing connections excluding lo
sudo nmcli con delete "Wired connection 1"
sudo nmcli con add type ethernet con-name "server-db" ifname eth0 ipv4.method manual ipv4.addresses "192.168.0.100/24"
sudo systemctl restart NetworkManager
```

- **Server**: attach 2 ethernet adapters — one to the internal network `server-db` (Int Net 1) and one to `vigilant-server` (Int Net 2) then run:

```bash
# Delete all existing connections excluding lo
sudo nmcli con delete "Wired connection 1"
sudo nmcli con add type ethernet con-name "server-db" ifname eth0 ipv4.method manual ipv4.addresses "192.168.0.10/24"
sudo nmcli con add type ethernet con-name "vigilant-server" ifname eth1 ipv4.method manual ipv4.addresses "192.168.100.2/24"
sudo systemctl restart NetworkManager
``` 

- **vigilant**: attach 2 ethernet adapters — one to the internal network `vigilant-server` (Int Net 2) and one to `peers-vigilant` (Int Net 3) then run:

```bash
# Delete all existing connections excluding lo
sudo nmcli con delete "Wired connection 1"
sudo nmcli con add type ethernet con-name "vigilant-server" ifname eth0 ipv4.method manual ipv4.addresses "192.168.100.1/24"
sudo nmcli con add type ethernet con-name "peers-vigilant" ifname eth1 ipv4.method manual ipv4.addresses "192.168.200.1/24"
sudo systemctl restart NetworkManager
```

- **Peer**: attach the Peer VM to the `peers-vigilant` internal network.

```bash
# Delete all existing connections excluding lo
sudo nmcli con delete "Wired connection 1"
# Select a random ip inside the subnetwork 
sudo nmcli con add type ethernet con-name "peers-vigilant" ifname eth1 ipv4.method manual ipv4.addresses "192.168.200.x/24"
sudo nmcli con add type ethernet con-name "NAT" ifname eth1 ipv4.method auto 
```

#### Step 1: Clone Repository (on all VMs)

```bash
git clone https://github.com/tecnico-sec/A10-DeathNode.git
cd A10-DeathNode
```

#### Step 2: Generate Certificates (on Server VM)

The project uses an internal Certificate Authority (CA) for mTLS. Run the certificate generation script:

```bash
cd /path/to/A10-DeathNode
bash scripts/generate_test_certs.sh
```

This automatically generates and places certificates in the correct directories:
- `shared/test_secrets/ca.pem` and `ca.key` (CA certificate and key)
- `server/certs/server.pem` and `server.key` (Server certificate)
- `server/certs/db_client.pem` and `db_client.key` (DB client certificate for server)
- `db/certs/db.pem` and `db.key` (Database server certificate)
- `shared/test_secrets/peer1/client.pem` and `client.key` (Peer 1 certificate)
- `shared/test_secrets/peer2/client.pem` and `client.key` (Peer 2 certificate)

The script handles certificate distribution automatically. You only need to copy the relevant directories to each VM:
- Database VM: Copy `db/certs/` directory
- Server VM: Copy `server/certs/` directory  
- Client VMs: Copy `shared/test_secrets/ca.pem` and the corresponding `peer{N}/` directory

### VM Deployment

#### Machine 1: Database VM (`deathnote-db`, 192.168.0.100)

This VM runs **PostgreSQL 17** with SSL/TLS enabled and certificate-based authentication.

**Setup Process:**

1. **Install PostgreSQL 17:**
```bash
# On Database VM
sudo apt update
sudo apt install postgresql-17 postgresql-contrib
```

2. **Configure PostgreSQL to use the certificates generated by the script:**
```bash
sudo cp db/certs/db.pem /var/lib/postgresql/17/main/server.crt
sudo cp db/certs/db.key /var/lib/postgresql/17/main/server.key
sudo cp shared/test_secrets/ca.pem /var/lib/postgresql/17/main/root.crt
sudo chown postgres:postgres /var/lib/postgresql/17/main/server.*
sudo chmod 600 /var/lib/postgresql/17/main/server.key
```

3. **Configure PostgreSQL for SSL:**

Edit `/etc/postgresql/17/main/postgresql.conf`:
```conf
ssl = on
ssl_cert_file = '/var/lib/postgresql/17/main/server.crt'
ssl_key_file = '/var/lib/postgresql/17/main/server.key'
ssl_ca_file = '/var/lib/postgresql/17/main/root.crt'

ssl_prefer_server_ciphers = on
ssl_ciphers = 'HIGH:!aNULL'

# look for listen_addresses
listen_addresses = '*'
```

Edit `/etc/postgresql/17/main/pg_hba.conf`:
```conf
# Require SSL and client certificate from server VM
#TYPE  DATABASE        USER            ADDRESS                 METHOD
hostssl  deathnode_db  app_worker      192.168.0.10/32         cert
hostssl  deathnode_db  shadow_admin    192.168.0.10/32         cert
```

4. **Create database and schema:**

```bash
# Run with sudo priviliges
chmod +x db/start_db.sh
./start_db.sh
```

**What the script does:**
- Checks if the PostgreSQL service is active; if not, it attempts to start it.
- Checks whether the `deathnode_db` database exists; if it does not, the script applies `schema.sql` to create the database and tables.
- Checks for seed data, if not present it applies `seed.sql` into `deathnode_db`.


5. **Configure firewall:**
```bash
cd /path/to/A10-DeathNode
sudo bash db/firewall_db.sh
```

This configures iptables to:
- Allow incoming TCP on port `5432` only from the server `192.168.0.10`.
- Allow ICMP (ping) from the server for basic network checks.
- Allow outgoing TCP/ICMP to the server `192.168.0.10`.
- Log blocked incoming packets with prefix `POSTGRES-BLOCKED:`.


**Verification:**
```bash
# Check PostgreSQL is listening on correct IP
sudo netstat -plnt | grep 5432
# Should show: 192.168.0.100:5432

# Check SSL is enabled
sudo -u postgres psql -c "SHOW ssl;"
# Should show: on
```

#### Machine 2: Server VM (`deathnote-server`, 192.168.0.10)

This VM runs the **Flask 3.0** REST API with mTLS enabled.

**Setup Process:**

1. **Install dependencies:**
```bash
sudo apt update
sudo apt install python3.11 python3-pip
cd /path/to/A10-DeathNode
pip3 install -r requirements.txt
```

2. **Set enviroment variables**
```bash
cd server
sudo ./setup_server.sh
. ./setup_server.sh
# Refer to `server/README.md` for full configuration details.
```

3. **Configure firewall:**
```bash
sudo bash server/firewall_server.sh
```

This configures iptables to:
- Allow incoming TCP on port `6000` from vigilant Service (`192.168.100.1`) on the public interface `eth1`.
- Allow outgoing TCP to vigilant Service (`192.168.100.1`) on `eth1` only for established connections.
- Allow incoming TCP from PostgreSQL (`192.168.0.100`) on the internal interface `eth0` only for established connections.
- Allow outgoing TCP to PostgreSQL (`192.168.0.100`) port `5432` on the internal interface `eth0`.

4. **Start server:**
```bash
cd server
python3 src/server.py
```

**Verification:**
```bash
# From Peer VM with client certificate 
curl --cacert ca.pem --cert peer1.pem --key peer1.key \
     https://192.168.200.1:6000/documents/last
# Expected: {"status": "ok"}
```

#### Machine 3: vigilant VM (`deathnote-vigilant`, 192.168.100.1 / 192.168.200.1)

This VM runs the **vigilant Service** that monitors and validates system activity between the server and clients.

**Setup Process:**

1. **Install dependencies:**
```bash
sudo apt update
sudo apt install python3.11 python3-pip
cd /path/to/A10-DeathNode
pip3 install -r requirements.txt
```

2. **Configure firewall:**
```bash
sudo bash vigilant/firewall_vigilant.sh
```

This configures iptables to:
- Allow incoming TCP on port `6000` on the public interface `eth1`.
- Allow outgoing TCP on `eth1` only for established connections.
- Allow incoming TCP from Server (`192.168.100.2`) on the internal interface `eth0` only for established connections.
- Allow outgoing TCP to Server (`192.168.100.2`) port `5000` on the internal interface `eth0`.

3. **Start vigilant:**
```bash
cd vigilant
python3 src/vigilant.py
```


#### Machine 4: Peer VMs (Clients)

Each peer VM runs the Python CLI client with certificate-based authentication.

**Setup Process:**

1. **Install dependencies:**
```bash
sudo apt update
sudo apt install python3.11 python3-pip
cd /path/to/A10-DeathNode
pip3 install -r requirements.txt
```

3. **Configure environment:**

Copy the peer certificate and key from the shared test secrets into the client VM. If you generated peers with `scripts/generate_test_certs.sh`, they are under `shared/test_secrets/peerN`.

```bash
# Refer to `client/README.md` for configuration details.
cp ../shared/test_secrets/peer{number}/* certs/
```

**CLI Commands:**
#### `protect`
Protect and encrypt a JSON document for the peer-to-peer network.

* **Usage:** `python main.py protect <input_file> <private_key> <shared_secret> <document_id> <output_file> [options]`
* **Arguments:**
    * `input_file`: Path to the source JSON document.
    * `private_key`: Path to the Signer's private key file (PEM format).
    * `shared_secret`: Path to the shared secret file used for KDF key derivation.
    * `document_id`: Numerical ID (`0`, `1`, `2`...) or `auto` to fetch the next available ID from the server.
    * `output_file`: Path where the protected document will be saved.
* **Options:**
    * `--prev-hash <file>`: Path to the previous document's hash file for chain verification.
    * `--server <url>`: Required if `document_id` is set to `auto`.

---

#### `unprotect`
Decrypt and unpack a protected document.

* **Usage:** `python main.py unprotect <input_file> <shared_secret> <output_file> [options]`
* **Arguments:**
    * `input_file`: Path to the encrypted/protected document.
    * `shared_secret`: Path to the shared secret file for decryption.
    * `output_file`: Path to save the decrypted bundle.
* **Options:**
    * `--prev-hash <file>`: Verify against the hash of the previous document in the chain.

---

#### `check`
Verify the cryptographic signature and internal hashes of an unprotected bundle.

* **Usage:** `python main.py check <input_file>`
* **Arguments:**
    * `input_file`: Path to the unprotected bundle file (containing data and signature).

---

#### `chain-verify`
Verify the integrity of a sequence of documents within a directory.

* **Usage:** `python main.py chain-verify <protected_dir> <shared_secret> [options]`
* **Arguments:**
    * `protected_dir`: Directory containing the encrypted document files.
    * `shared_secret`: Path to the shared secret file.
* **Options:**
    * `--local-docs <dir>`: Directory containing local unprotected copies for comparison (should be safe docs to be a reliable comparison).
    * `--prev-hash <file>`: Start verification from this specific previous hash file.

---

#### `users`
List all registered users and their public keys from the server.

* **Usage:** `python main.py users --server <url>`
    * `--server <url>`: The vigilant URL

---

#### `upload`
Upload a protected document to the central server.

* **Usage:** `python main.py upload <protected_file> --server <url>`
* **Arguments:**
    * `protected_file`: Path to the protected JSON file.
    * `--server <url>`: The vigilant URL 

---

#### `server-status`
Check the connection and current status of the main server.

* **Usage:** `python main.py server-status --server <url>`
    * `--server <url>`: The vigilant URL.

---

#### `vigilant-status`
Check the status of the vigilant monitoring node.

* **Usage:** `python main.py vigilant-status --server <url>`
    * `--server <url>`:  The vigilant node URL.

---

#### `download`
Download protected bunldes from the server to the local system.

* **Usage:** `python main.py download --server <url> [options]`
* **Options:**
    * `--server <url>`: **(Required)** The vigilant URL.
    * `--since-id <int>`: Start downloading documents from this ID (default: `0`).
    * `--limit <int>`: Maximum number of documents to download (default: `100`).
    * `--shared-secret <file>`: If provided, the CLI will automatically decrypt and save documents as bundles in a specific dr (it will still save protected bundles in the respective dir).


## Demonstration

Now that all the networks and machines are up and running, we'll demonstrate the key security features.

### Normal workflow

1. Protect a document

`python3 src/main.py protect tests/test_data/sample1.json certs/client.key tests/test_secrets/shared_secret.bin auto protected1.json --server https://192.168.200.1:6000`

2. Upload document

`python3 src/main.py upload --server https://192.168.200.1:6000 protected1.json`

3. Protect a second document

`python3 src/main.py protect tests/test_data/sample2.json certs/client.key tests/test_secrets/shared_secret.bin auto protected2.json --server https://192.168.200.1:6000 --prev-hash protected1.json.chain_hash`

4. Upload a second document

`python3 src/main.py upload --server https://192.168.200.1:6000 protected2.json` 

5. Fetch documents from server

`python3 src/main.py download --server https://192.168.200.1:6000` 

6. Verify chain hash

`python3 src/main.py chain-verify /home/joao/deathnote_client/pro_documents tests/test_secrets/shared_secret.bin` 

#### Workflow showcase 

```bash
python3 src/main.py protect tests/test_data/sample1.json certs/client.key tests/test_secrets/shared_secret.bin auto protected1.json --server https://192.168.200.1:6000
Auto-fetched next document ID: 1
Protecting document: tests/test_data/sample1.json
[OK] Protected document saved: protected1.json
[OK] Chain hash saved: protected1.json.chain_hash
[INFO] Use --prev-hash protected1.json.chain_hash for next document (creates blockchain-style chain)
                                                                                                                                                                                             
python3 src/main.py upload --server https://192.168.200.1:6000 protected1.json
Local ciphertext hash: 326438936c9bf02e...
Document ID in payload: 1
Uploading to https://192.168.200.1:6000/documents...
  Client last_id: 0

✓ Document uploaded successfully!
  Document ID: 1
  Server hash: 326438936c9bf02e...
  Hash verification: ✓ PASSED
                                                                                                                                                                                             
python3 src/main.py protect tests/test_data/sample2.json certs/client.key tests/test_secrets/shared_secret.bin auto protected2.json --server https://192.168.200.1:6000 --prev-hash protected1.json.chain_hash
Auto-fetched next document ID: 2
Protecting document: tests/test_data/sample2.json
[OK] Protected document saved: protected2.json
[OK] Chain hash saved: protected2.json.chain_hash
[INFO] Use --prev-hash protected2.json.chain_hash for next document (creates blockchain-style chain)
                                                                                                                                                                                             
python3 src/main.py upload --server https://192.168.200.1:6000 protected2.json 
Local ciphertext hash: 9aaf7628b529eb8f...
Document ID in payload: 2
Uploading to https://192.168.200.1:6000/documents...
  Client last_id: 1

✓ Document uploaded successfully!
  Document ID: 2
  Server hash: 9aaf7628b529eb8f...
  Hash verification: ✓ PASSED
                                                                                                                                                                                             
python3 src/main.py download --server https://192.168.200.1:6000 --shared-secret tests/test_secrets/shared_secret.bin 

=== Downloading Documents ===
Fetched 2 documents from server

Saving to: /home/joao/deathnote_client
  ✓ Saved encrypted: pro_documents/doc_1.protected.json
  ✓ Saved bundle: un_bundles/bundle_1.json
  ✓ Saved encrypted: pro_documents/doc_2.protected.json
  ✓ Saved bundle: un_bundles/bundle_2.json

 Download complete!
   Encrypted docs: /home/joao/deathnote_client/pro_documents
   Unencrypted bundles: /home/joao/deathnote_client/un_bundles
   Sync state: /home/joao/deathnote_client/.cache/sync_state.json
   Has more: False
                                                                                                                                      
python3 src/main.py chain-verify /home/joao/deathnote_client/pro_documents tests/test_secrets/shared_secret.bin 
Found 2 protected documents
Verifying document chain (decrypting and verifying signatures)...

============================================================
CHAIN VERIFICATION RESULT
============================================================
[VALID] All 2 documents verified

Documents verified: 2

  [PASS] Document 0:
      [PASS] document_id: True
      [PASS] decryption: True
      [PASS] signature: True
      [PASS] document_hash: True
      [INFO] chain_hash: first_document
      [INFO] tampering_check: new_document
      [INFO] duplicate_content_check: unique

  [PASS] Document 1:
      [PASS] document_id: True
      [PASS] decryption: True
      [PASS] signature: True
      [PASS] document_hash: True
      [PASS] chain_hash: True
      [INFO] tampering_check: new_document
      [INFO] duplicate_content_check: unique
============================================================
```

### Demo 1: Basic Case

**Scenario:** Peer1 submits a report that can only be decrypted by users with who have the secret.

```bash
# 1. Create a confidential report
cat > /tmp/incident.json << EOF
{
  "report_id": "abc123",
  "timestamp": "2025-10-28T12:00:00Z",
  "reporter_pseudonym": "peer1",
  "content": {
    "suspect": "john_doe",
    "description": "Alleged involvement in organized crime",
    "location": "Tokyo, Japan"
  },
  "version": 2,
  "status": "pending_validation"
}
EOF

# 2. Protect document (Peer1 signs)
python3 src/main.py protect tests/test_data/sample_report.json keys/client.key tests/test_secrets/shared_secret.bin 1 protected.json  

# Expected output:
# Document ID: 1
# Protecting document: tests/test_data/sample_report.json
# [OK] Protected document saved: protected.json
# [OK] Document hash saved: protected.json.hash
# [OK] Chain hash saved: protected.json.chain_hash
# [INFO] Use --prev-hash protected.json.chain_hash for next document (creates blockchain-style chain)

```

**View the protected format:**
```bash
cat /tmp/incident.protected.json
```

**Encrypted Document:**
```json
{
  "encrypted_payload": {
    "ciphertext": "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",
    "nonce": "0t3eJ0EkOQTovM3t",
    "metadata": {
      "document_id": 1,
      "algorithm": "AES-256-GCM",
      "signature_algorithm": "RSA-PSS-SHA256",
      "kdf_algorithm": "HKDF-SHA256",
      "protected_at": "2025-12-13T15:28:07.484450Z",
      "reporter_pseudonym": "peer1"
    }
  },
  "payload_signature": "lkdmAcijk7Lq16dyAXNoXYE7k4a1Uwq0Vqm2n/GPcFyYlggxq78gn4x4mhcCmi0oOvT8YzVsSEDtEV5VhVfqOIpGazgvt0Sg0UHeKzV54CAiljINCTpHD4VXfkMtbpExfgv2i9YVn4rQU4CtdlUBnz3BRmJHhQH/iWzG4iRfQexx5emdVKwBDHlEir27b/FeV3q3fiIRubRaCTk+dqhqliuJrPCVFHDmADHxVd7jdGslzxTZPc60kiMqsRxCiCDxR3j0r1ExsKRlKUueboGdPXAaOIptGjJKms1W0Bi1v/gh4oYQeItJLwzjEByymRUxbtDEFzhor6PZWnBcMR5jfjXfYgNiuYmPOmmvz7Niw5Ya5/qH+6RZku4ozPFadCerTIYiuUIOXnqA8WgVH7j8Vq5cwMWevmBd7E+Gpj2U9Rtnfpj16wy6P6sZm+ZdNwcHIxfI9/wnBgTH+CwM/7/aZWox1vOYrSFSZ1P3CuZpgHhmYzPdeKQqvafSYRzU9j7sRleaOvNW9Q19uB1yMRk/WDvBbAbzeQOQiGcbKmgWZop2IQkNED7f0mFQJkdjsWM+BbAa7qSF0KXWdJlnD1G2HjhkTMCkzPRd6AvUM6Pm7QhQ9/S9cVZ5Jr6MWaMGiXj580LsCq0AlNlGK2mfCHWEPNm1ia6LJVL8IUXuoYs/CzE=",
  "payload_hash": "M013tMDrDwAc4dsq5jCwISllzfrx0a2r5PA6+4W8msCizO6bHMMz7utIxPSGjpPWDTf0g8sg80c+JrzytZE65HD17pwbm2F10wFjy01sJPQCV2JRGUKclkRDijvzOy/F6VbEPmrpQUrz/R1oOmtdIn0DSAaAiJBeW8YgXmVvDOS6LNVQN3AttJevABicfMCLOWQt3b6EcZY4uNh5NTe0AoP+vBrdUKgDkGC88l+3qF5KUo6gONkW18byaa7sVDDmpv+ErVYfoGslEQP15apDvX7909hNbZ+DTLUygYQOMCfdFE0SHiVkrNzfucaVAhTBkFh2lxKW1uL5Ianzovoy6L="
} 
```

**Security mechanisms visible:**
-  Ciphertext is base64-encoded AES-256-GCM encrypted data (confidentiality)
-  Every recepient has the shared secret and a key derivation function that generates a AES key
-  Signature proves Peer1 created it (authenticity)
-  Unique nonce prevents replay attacks (freshness)

#### **SR1:** Confidentiality Only authorized nodes in the peer-to-peer network can decrypt reports.

Outsiders don't have the shared secret so they can't derivate the public key to decrypt the documents.

### Demo 2: Tamper Detection (SR2)

**Test integrity protection:**

Unprotected document
```bash
python3 src/main.py unprotect tests/test_data/protected.json tests/test_secrets/shared_secret.bin unprotected.json
Unprotecting document: tests/test_data/protected.json
[OK] Unprotected bundle saved: unprotected.json
[OK] Document extracted to: unprotected.document.json

cat unprotected.json 
{
  "chain_hash": "ziHkJ88vwczeGd0SQciboAovKiIQL+h3s0raqCeTaM0=",
  "document": {
    "content": {
      "description": "Alleged involvement in organized crime",
      "location": "Tokyo, Japan",
      "suspect": "john_doe"
    },
    "report_id": "abc123",
    "reporter_pseudonym": "peer1",
    "status": "pending_validation",
    "timestamp": "2025-10-28T12:00:00Z",
    "version": 2
  },
  "document_hash": "WumYAoL0E9BcJSPYlJLBxoIg8QGGl2k+AkU4GYi0rB8=",
  "signature": "M013tMDrDwAc4dsq5jCwISllzfrx0a2r5PA6+4W8msCizO6bHMMz7utIxPSGjpPWDTf0g8sg80c+JrzytZE65HD17pwbm2F10wFjy01sJPQCV2JRGUKclkRDijvzOy/F6VbEPmrpQUrz/R1oOmtdIn0DSAaAiJBeW8YgXmVvDOS6LNVQN3AttJevABicfMCLOWQt3b6EcZY4uNh5NTe0AoP+vBrdUKgDkGC88l+3qF5KUo6gONkW18byaa7sVDDmpv+ErVYfoGslEQP15apDvX7909hNbZ+DTLUygYQOMCfdFE0SHiVkrNzfucaVAhTBkFh2lxKW1uL5Ianzovoy6LzSyeczxa8ZgeyRzQ9LRDLn1raIk9xXbW0psuqP0zJjsLhCvu/SOt564CPqbASwBCZKx/VZR59+0hI0OHTtK7p+5AVSeSjm7emrPH0Or0K75s6nNZJy4Ymys7AXhahxUBth4Qa34l0X3GJ4qFjGpkLCFSH3nBLwele1It8E0dO9cc6mwie2mMcolrmArCNxo4hOYQyv8alWzLe6PQQsYkaKSVBGuzg+rCZ5shCMN6rA/UhSYcvlVWTib8bz5IC0/g+c+rYU1KCHP4X3ElRGpg7iFtu0cFRO9XncExBZ6x8QPkh/dqjtDTaHrh5Caiy3TI9I/u+pd1RYdtuWLN++kxc=",
  "signer_public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUFvYjlHZk1heTVBS1pkb3hiZFZUaQpKN2x5eHV4dG1yTG5FQ0hPT0VFYnlESDc1TUFzalNsYzNIbFZZd1R6eGxvSldUQXF5cGM3OGpWRUdaR29YWlJoClp3ZUl6Z3pIWHJTMTNYL05OZm9tN3gvcUhncUw0WmJRZ0FZelpMU1JyOHZ6dXllTThCdE5PcjBCNytiZHU3Nk0KMnFFam1JdjV2cnR3RlVxWmY5VnYvUE90K1d0bGtNNjVTNWFCQUp3bGU0K2tRWTl3a3J6d01JalBjeENJR1FNWQpLdDE0WlBrblVtaXFNbzNjZGJMQkxHR0c3U2FCUlBxa0VFNENKNTZ3L3Fvd3hTMWJXVjNadW41OWNJdFkxSkJRClpzTURzeVZhclNXSTJXdzVrajNObUl2MG05N1Q0YXRTQ253MzdXWVlyWnF4aDBPd3kxaXRnZ3VxM2d2UFJPSWgKTlpzUDhZUXJsSVgxKzd1dnlXZDNXRVl4RytBWTVreG5xZVduZ1Z3S2UyZlFPSGRCeHdLbVJxckU4WUc0RVY4WQp5L0FQZ1lWWm9NQlQ0WmkrWHdGOFdyUE1Uc0JwclZBRU9UVk9pYmhObExZZjFLZ1Y3S3oyNmJzeHlodWlFQWRLClVVVzZBT0hlVXg0OEZuRFRGdE9xTGs5VkZIdmZ3UThmTnl0Q1FCalhTMXc0bGNXWC9jVzZ1YUJSZnRON3FqQ2QKSWV2N3Z6T1J0MVlKcG91bzlMUFR1dUlIekx5NW01RFd6Q0RVK1NpTC9aTTNwYTBJRXc2SGc4MUJRWE92eXEzMwpNc0RmaVpCRjNIckJHbTlFdXhrTkhxUndBb0JCakN0S2ZwdS9tM3U5RnhWb1VDRW03ME5Qc0NuaTMwYkdBTStWCnlHenVHZXRCVmdrc2VFeWg0TWJrVlJFQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
}
```

Output without tempering
```bash
python3 src/main.py check unprotected.json 
Checking document: unprotected.json

============================================================
DOCUMENT VALIDATION RESULT
============================================================
[VALID] Document passed all checks
  Signer: a2916601ac48fdc3
   document_hash: True
   signature: True
```

Output of a valid chain hash
```bash
python3 src/main.py chain-verify ../../deathnote_client/pro_documents tests/test_secrets/shared_secret.bin
Found 2 protected documents
Verifying document chain (decrypting and verifying signatures)...

============================================================
CHAIN VERIFICATION RESULT
============================================================
[VALID] All 2 documents verified

Documents verified: 2

  [PASS] Document 0:
      [PASS] document_id: True
      [PASS] decryption: True
      [PASS] signature: True
      [PASS] document_hash: True
      [INFO] chain_hash: first_document
      [INFO] tampering_check: new_document
      [INFO] duplicate_content_check: unique

  [PASS] Document 1:
      [PASS] document_id: True
      [PASS] decryption: True
      [PASS] signature: True
      [PASS] document_hash: True
      [PASS] chain_hash: True
      [INFO] tampering_check: new_document
      [INFO] duplicate_content_check: unique
============================================================
```                                                                                                                     
Ouput with a tempered signature
```bash
python3 src/main.py check unprotected.json
Checking document: unprotected.json

============================================================
DOCUMENT VALIDATION RESULT
============================================================
[INVALID] Document failed validation
  ✗ Invalid signature - document may be tampered
```

Output with a tempered payload
```bash
python3 src/main.py check unprotected.json                                                                        
Checking document: unprotected.json

============================================================
DOCUMENT VALIDATION RESULT
============================================================
[INVALID] Document failed validation
  ✗ Document hash mismatch - integrity check failed
  ✗ Invalid signature - document may be tampered                                                                         
```


### Demo 3: Chain Integrity  (SR3)

#### Missing document detection
1. Delete a document from the database
```sql
DELETE FROM documents WHERE id = 1;
```

```bash
python3 src/main.py chain-verify ../../deathnote_client/pro_documents tests/test_secrets/shared_secret.bin --local-docs ../../deathnote_client/un_bundles
Found 1 protected documents
Loaded 2 local documents for comparison
Verifying document chain (decrypting and verifying signatures)...

============================================================
CHAIN VERIFICATION RESULT
============================================================
[INVALID] Chain verification failed

Documents verified: 1

  [FAIL] Document 0:
      [FAIL] document_id: False
      [FAIL] decryption: False
      [FAIL] signature: False
      [FAIL] document_hash: False
      [FAIL] chain_hash: False
      [INFO] tampering_check: error
      • Document ID mismatch: expected 1, got 2

Chain errors:
  • Document 0 (ID=2) failed verification
============================================================
```

#### Document out of order detection
1. Change the order of the documents in the database
```sql
BEGIN;
UPDATE documents SET encrypted_payload = (SELECT encrypted_payload FROM documents WHERE id = 3) WHERE id = 2;
UPDATE documents SET encrypted_payload = (SELECT encrypted_payload FROM documents WHERE id = 2) WHERE id = 3;
COMMIT;
```

```bash
python3 src/main.py chain-verify /home/joao/deathnote_client/pro_documents tests/test_secrets/shared_secret.bin
Found 3 protected documents
Verifying document chain (decrypting and verifying signatures)...
[WARNING] Document 3 has identical content to document 1

============================================================
CHAIN VERIFICATION RESULT
============================================================
[INVALID] Chain verification failed

Documents verified: 3

  [PASS] Document 0:
      [PASS] document_id: True
      [PASS] decryption: True
      [PASS] signature: True
      [PASS] document_hash: True
      [INFO] chain_hash: first_document
      [INFO] tampering_check: new_document
      [INFO] duplicate_content_check: unique

  [FAIL] Document 1:
      [FAIL] document_id: False
      [FAIL] decryption: False
      [FAIL] signature: False
      [FAIL] document_hash: False
      [FAIL] chain_hash: False
      [INFO] tampering_check: error
      • Document ID mismatch: expected 2, got 3

  [FAIL] Document 2:
      [PASS] document_id: True
      [FAIL] decryption: False
      [FAIL] signature: False
      [FAIL] document_hash: False
      [FAIL] chain_hash: False
      [INFO] tampering_check: error
      • Chain hash verification FAILED for new document 3! Computed: S9yurhjL9BP63zOnNEyXQnJJCH15+HAw... Stored: ziHkJ88vwczeGd0SQciboAovKiIQL+h3...

Chain errors:
  • Document 1 (ID=3) failed verification
  • Document 2 (ID=3) failed verification
============================================================
```

**Security validated:** Each document's `previous_hash` matches previous document's `document_hash`

## Security Challenge Demos

### Demo 4: Signature Forgery Prevention

**Attempt to forge signature:**
```bash
python3 src/main.py upload ../data/protected/report0.json  --server https://192.168.200.1:6000/
Local ciphertext hash: ac21be90325f85a8...
Document ID in payload: 1
Uploading to https://192.168.200.1:6000/documents...
  Client last_id: 0

 UPLOAD FORBIDDEN: Impersonation detected - signer banned
   Reason: Payload was signed by user 'peer1' but claimed reporter 'peer2'.
   Details: Banned until 2025-12-18T00:47:48.509824
   Action: Signer has been banned for 60 minutes for impersonation
```

### Demo 5: Duplicated document detection
Output on uploading a equal payload
```bash
python3 src/main.py upload --server https://192.168.200.1:6000 protected.json
Local ciphertext hash: 57c0883e093d9920...
Document ID in payload: 2
Uploading to https://192.168.200.1:6000/documents...
  Client last_id: 1

 UPLOAD FORBIDDEN: Replay attack detected
   Reason: This payload has already been submitted
   Details: Your IP has been banned for 60 minutes
```

### Demo 6: Spam atacks detection
Output after uploading 3 documents in a span of 30 min
```bash
└─$ python3 src/main.py upload --server https://192.168.200.1:6000 protected.json                                                                                         
Local ciphertext hash: 5f16bca567df399c...
Document ID in payload: 6
Uploading to https://192.168.200.1:6000/documents...
  Client last_id: 5

 UPLOAD FORBIDDEN: Spam detected - user and IP banned
   Reason: Too many uploads in a short time period
   Details: Banned until 2025-12-18T16:28:31.900978
   Action: User has been banned for 30 minutes for spamming. Your IP has also been banned.
``` 

## Additional Information

### Links to Used Tools and Libraries

- [Python 3.11](https://www.python.org/downloads/)
- [cryptography library](https://cryptography.io/) - Cryptographic primitives
- [Flask 3.0.0](https://flask.palletsprojects.com/) - Web framework
- [PostgreSQL 17](https://www.postgresql.org/) - Database
- [psycopg2](https://www.psycopg.org/) - PostgreSQL adapter
- [requests](https://requests.readthedocs.io/) - HTTP library

### Versioning

We use [SemVer](http://semver.org/) for versioning.  

### License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) for details.


----
END OF README
                                       