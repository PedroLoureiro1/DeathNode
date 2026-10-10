#!/usr/bin/env python3
import sys
import json
import os
import argparse
import requests
import ssl
import urllib3
import base64
from pathlib import Path


# Add shared folder to path to import deathnote_lib
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'shared'))

from deathnote_lib import (
    protect,
    check,
    unprotect,
    verify_chain,
    get_chain_hash,
    compute_hash,
    ProtectionError
)

# Certificate paths
CLIENT_DIR = Path(__file__).parent.parent
CERTS_DIR = CLIENT_DIR / 'certs'
CA_CERT = CLIENT_DIR.parent / 'shared' / 'test_secrets' / 'ca.pem'

# Client certificate for mTLS (can be overridden by environment variables)
CLIENT_CERT = os.getenv('CLIENT_CERT', str(CERTS_DIR / 'client.pem'))
CLIENT_KEY = os.getenv('CLIENT_KEY', str(CERTS_DIR / 'client.key'))

def _validate_server_url(server_url: str):
    from urllib.parse import urlparse
    
    parsed = urlparse(server_url)
    
    # Check if port is specified
    if not parsed.port:
        print("ERROR: Server URL must include port number", file=sys.stderr)
        print(f"  Your URL: {server_url}", file=sys.stderr)
        print(f"  Expected: {parsed.scheme}://{parsed.hostname}:6000", file=sys.stderr)
        print(f"  Example: https://192.168.200.1:6000", file=sys.stderr)
        sys.exit(1)


def _create_tls_session():
    """Create a requests Session with custom TLS configuration that supports mTLS."""
    from requests.adapters import HTTPAdapter
    
    # Disable SSL warnings for self-signed certificates
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    class TLSAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            
            # Load CA certificate to verify server
            ctx.load_verify_locations(cafile=str(CA_CERT))
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            
            # Load client certificate for mTLS if available
            if os.path.exists(CLIENT_CERT) and os.path.exists(CLIENT_KEY):
                ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
            
            # Set minimum TLS version to match server
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            
            # Allow strong ciphers only
            ctx.set_ciphers('DEFAULT@SECLEVEL=1')
            
            kwargs['ssl_context'] = ctx
            return super().init_poolmanager(*args, **kwargs)
            
    session = requests.Session()
    session.mount('https://', TLSAdapter())
    return session

def cmd_protect(args):
    """Protect a document for peer-to-peer network."""
    try:
        # Read input document
        with open(args.input_file, 'r') as f:
            document = json.load(f)
        
        # Get document_id - either from CLI arg or fetch from server
        if args.document_id == 'auto':
            if not args.server:
                print("ERROR: --server required when document_id is 'auto'", file=sys.stderr)
                sys.exit(1)
            # Validate server URL includes port
            _validate_server_url(args.server)
            # Fetch next ID from server
            try:
                session = _create_tls_session()
                response = session.get(f"{args.server}/documents/last", timeout=10, verify=True)
                response.raise_for_status()
                status = response.json()
                if status.get('document_id') is not None:
                    document_id = status['document_id'] + 1
                else:
                    document_id = 1
                print(f"Auto-fetched next document ID: {document_id}")
            except Exception as e:
                print(f"ERROR: Failed to fetch document ID from server: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # Use provided document_id
            try:
                document_id = int(args.document_id)
            except ValueError:
                print(f"ERROR: document_id must be a number or 'auto'", file=sys.stderr)
                sys.exit(1)
            print(f"Document ID: {document_id}")
        
        # Read signer's private key
        with open(args.private_key, 'rb') as f:
            private_key_pem = f.read()
        
        # Read shared secret for KDF
        with open(args.shared_secret, 'rb') as f:
            shared_secret = f.read()
        
        # Read previous hash if provided
        prev_hash = None
        if args.prev_hash:
            with open(args.prev_hash, 'rb') as f:
                prev_hash = base64.b64decode(f.read())
        
        # Protect document using KDF-based key derivation with document_id as salt
        print(f"Protecting document: {args.input_file}")
        protected = protect(document, private_key_pem, shared_secret=shared_secret, 
                          document_id=document_id, prev_hash=prev_hash)
        
        # Save protected document
        with open(args.output_file, 'w') as f:
            json.dump(protected, f, indent=2)
        print(f"[OK] Protected document saved: {args.output_file}")
        
        # Save chain hash (IMPORTANT: use this as --prev-hash for next document)
        chain_hash_file = args.output_file + ".chain_hash"
        chain_hash = get_chain_hash(protected, shared_secret)
        with open(chain_hash_file, 'wb') as f:
            f.write(base64.b64encode(chain_hash))
        print(f"[OK] Chain hash saved: {chain_hash_file}")
        print(f"[INFO] Use --prev-hash {chain_hash_file} for next document (creates blockchain-style chain)")
        
    except FileNotFoundError as e:
        print(f"ERROR: File not found: {e.filename}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in input file: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except ProtectionError as e:
        print(f"ERROR: Protection failed: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Unexpected error: {str(e)}", file=sys.stderr)
        sys.exit(1)


def cmd_unprotect(args):
    """Unprotect a document."""
    try:
        # Read protected document
        with open(args.input_file, 'r') as f:
            protected = json.load(f)
        
        # Read shared secret for KDF
        with open(args.shared_secret, 'rb') as f:
            shared_secret = f.read()
        
        # Read previous hash if provided
        prev_hash = None
        if args.prev_hash:
            with open(args.prev_hash, 'rb') as f:
                prev_hash = base64.b64decode(f.read())
        
        # Unprotect document using KDF-based key derivation
        print(f"Unprotecting document: {args.input_file}")
        bundle = unprotect(protected, shared_secret, prev_hash=prev_hash)
        
        # Save unprotected bundle (includes document + signature + hashes)
        # This can be used with 'check' command for validation
        with open(args.output_file, 'w') as f:
            json.dump(bundle, f, indent=2)
        print(f"[OK] Unprotected bundle saved: {args.output_file}")
        
        # Also save just the document for convenience
        document_file = args.output_file.replace('.json', '.document.json')
        if document_file == args.output_file:
            document_file = args.output_file + '.document'
        with open(document_file, 'w') as f:
            json.dump(bundle['document'], f, indent=2)
        print(f"[OK] Document extracted to: {document_file}")
        
    except FileNotFoundError as e:
        print(f"ERROR: File not found: {e.filename}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in input file: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except ProtectionError as e:
        print(f"ERROR: Unprotect failed: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Unexpected error: {str(e)}", file=sys.stderr)
        sys.exit(1)


def cmd_check(args):
    """Check an unprotected document's signature and hashes."""
    try:
        # Read unprotected document (must be a bundle with signature)
        with open(args.input_file, 'r') as f:
            bundle = json.load(f)
        
        print(f"Checking document: {args.input_file}")
        result = check(bundle)
        
        # Print results
        print("\n" + "="*60)
        print("DOCUMENT VALIDATION RESULT")
        print("="*60)
        
        if result['valid']:
            print("[VALID] Document passed all checks")
            print(f"  Signer: {result.get('signer_key_fingerprint', 'unknown')}")
            for check_name, status in result['checks'].items():
                print(f"   {check_name}: {status}")
        else:
            print("[INVALID] Document failed validation")
            for error in result['errors']:
                print(f"  ✗ {error}")
            sys.exit(1)
        
    except FileNotFoundError as e:
        print(f"ERROR: File not found: {e.filename}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in input file: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except KeyError as e:
        print(f"ERROR: Invalid document format - missing key: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Unexpected error: {str(e)}", file=sys.stderr)
        sys.exit(1)


def cmd_chain_verify(args):
    """Verify a chain of protected documents."""
    try:
        # Read shared secret for KDF
        with open(args.shared_secret, 'rb') as f:
            shared_secret = f.read()
        
        # Find all protected documents
        protected_dir = Path(args.protected_dir)
        protected_files = sorted(protected_dir.glob("*.protected.json"))
        
        if not protected_files:
            print(f"ERROR: No protected documents found in {args.protected_dir}", file=sys.stderr)
            sys.exit(1)
        
        print(f"Found {len(protected_files)} protected documents")
        
        # Load all documents
        documents = []
        for file_path in protected_files:
            with open(file_path, 'r') as f:
                documents.append(json.load(f))
        
        # Read previous hash if provided
        prev_hash = None
        if args.prev_hash:
            with open(args.prev_hash, 'rb') as f:
                prev_hash = base64.b64decode(f.read())

        # Load local documents if provided
        local_documents = None
        if args.local_docs:
            local_dir = Path(args.local_docs)
            local_files = sorted(local_dir.glob("*.json"))
            if local_files:
                local_documents = []
                for file_path in local_files:
                    with open(file_path, 'r') as f:
                        local_documents.append(json.load(f))
                print(f"Loaded {len(local_documents)} local documents for comparison")
            else:
                print(f"Warning: No local documents found in {args.local_docs}")
        
        # Verify chain using KDF-based key derivation
        print(f"Verifying document chain (decrypting and verifying signatures)...")
        
        result = verify_chain(documents, shared_secret, local_documents, prev_hash)
        
        # Print results
        print("\n" + "="*60)
        print("CHAIN VERIFICATION RESULT")
        print("="*60)
        
        if result['valid']:
            print(f"[VALID] All {result['total_documents']} documents verified")
        else:
            print(f"[INVALID] Chain verification failed")
        
        print(f"\nDocuments verified: {result['total_documents']}")
        
        for doc_result in result['documents']:
            status = "[PASS]" if doc_result['valid'] else "[FAIL]"
            print(f"\n  {status} Document {doc_result['index']}:")
            for check_name, check_result in doc_result['checks'].items():
                check_status = "[PASS]" if check_result == True else ("[FAIL]" if check_result == False else "[INFO]")
                print(f"      {check_status} {check_name}: {check_result}")
            
            if doc_result.get('errors'):
                for error in doc_result['errors']:
                    print(f"      • {error}")
        
        if result.get('errors'):
            print("\nChain errors:")
            for error in result['errors']:
                print(f"  • {error}")
        
        print("="*60)
        
        sys.exit(0 if result['valid'] else 1)
        
    except FileNotFoundError as e:
        print(f"ERROR: File not found: {e.filename}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Unexpected error: {str(e)}", file=sys.stderr)
        sys.exit(1)


# ============================================================================
# SERVER INTERACTION COMMANDS
# ============================================================================

def cmd_users(args):
    """Get list of users and their public keys from server."""
    try:
        _validate_server_url(args.server)
        session = _create_tls_session()
        response = session.get(f"{args.server}/users", timeout=10, verify=True)
        response.raise_for_status()
        users = response.json()
        
        if not users:
            print("No users registered on server")
        else:
            print(f"\n=== Registered Users ({len(users)}) ===\n")
            for user in users:
                print(f"Username: {user['username']}")
                print(f"Public Key:\n{user['public_key']}")
                print("-" * 60)
        
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Server request failed: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)


def cmd_upload(args):
    """Upload a protected document to the server."""
    try:
        _validate_server_url(args.server)
        # Read protected document (already encrypted)
        with open(args.protected_file, 'r') as f:
            protected = json.load(f)
        
        # Extract the encrypted payload and payload_signature
        if 'encrypted_payload' not in protected:
            print("ERROR: Invalid protected document format", file=sys.stderr)
            sys.exit(1)
        
        encrypted_payload = protected['encrypted_payload']
        payload_signature = protected.get('payload_signature')
        payload_hash = protected.get('payload_hash')  # Extract payload_hash
        metadata = encrypted_payload.get('metadata', {})
        document_id = metadata.get('document_id')
        
        # Compute local hash
        ciphertext = base64.b64decode(encrypted_payload.get('ciphertext', ''))
        local_hash = compute_hash(ciphertext).hex()
        print(f"Local ciphertext hash: {local_hash[:16]}...")
        print(f"Document ID in payload: {document_id}")
        
        # Client's last_id is (document_id - 1) since this is the NEXT document
        if document_id is not None:
            client_last_id = document_id - 1
        else:
            print("ERROR: Document ID not found in metadata", file=sys.stderr)
            sys.exit(1)
        
        # Upload to server (server will check if client is synchronized using ID only)
        print(f"Uploading to {args.server}/documents...")
        print(f"  Client last_id: {client_last_id}")
        
        upload_data = {
            'encrypted_payload': encrypted_payload,
            'payload_hash': payload_hash,
            'payload_signature': payload_signature,
            'client_last_id': client_last_id
        }
        
        session = _create_tls_session()
        response = session.post(
            f"{args.server}/documents",
            json=upload_data,
            timeout=30,
            verify=True
        )
        
        # Handle synchronization errors from server
        if response.status_code == 409:
            error_data = response.json()
            print(f"\n UPLOAD REJECTED: {error_data.get('error')}", file=sys.stderr)
            print(f"   Reason: {error_data.get('reason')}", file=sys.stderr)
            if 'server_state' in error_data:
                state = error_data['server_state']
                print(f"\n   Server State:", file=sys.stderr)
                print(f"     Last ID: {state.get('last_document_id')}", file=sys.stderr)
                print(f"     Next ID: {state.get('next_document_id')}", file=sys.stderr)
                print(f"     Total Docs: {state.get('total_documents')}", file=sys.stderr)
            print(f"\n   Action: {error_data.get('action')}", file=sys.stderr)
            sys.exit(1)
        
        # Handle ban/rejection errors from vigilant
        if response.status_code >= 400:
            try:
                error_data = response.json()
                error_type = error_data.get('error', 'Access denied')
                reason = error_data.get('reason', 'Unknown')
                action = error_data.get('action', '')
                details = error_data.get('details', '')
                
                print(f"\n UPLOAD FORBIDDEN: {error_type}", file=sys.stderr)
                print(f"   Reason: {reason}", file=sys.stderr)
                if details:
                    print(f"   Details: {details}", file=sys.stderr)
                if action:
                    print(f"   Action: {action}", file=sys.stderr)
                    
            except json.JSONDecodeError:
                print(f"\n UPLOAD FORBIDDEN: Access denied (403)", file=sys.stderr)
                print(f"   Reason: User/IP may be banned or unauthorized", file=sys.stderr)
            sys.exit(1)
        
        response.raise_for_status()
        
        result = response.json()
        print(f"\n✓ Document uploaded successfully!")
        print(f"  Document ID: {result['document_id']}")
        print(f"  Server hash: {result['ciphertext_hash'][:16]}...")
        
        # Verify hash matches
        if result['ciphertext_hash'] == local_hash:
            print(f"  Hash verification: ✓ PASSED")
        else:
            print(f"  Hash verification: ✗ WARNING - Mismatch!")
        
    except FileNotFoundError as e:
        print(f"ERROR: File not found: {e.filename}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Server request failed: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)


def cmd_status(args):
    """Get server status."""
    try:
        _validate_server_url(args.server)
        session = _create_tls_session()
        response = session.get(f"{args.server}/documents/last", timeout=10, verify=True)
        response.raise_for_status()
        status = response.json()
        
        print("\n=== Server Status ===")
        if status.get('document_id') is not None:
            last_id = status['document_id']
            next_id = last_id + 1
            print(f"Last Document ID: {last_id}")
            print(f"Next Document ID: {next_id}")
            print(f"Last Hash: {status.get('ciphertext_hash', 'N/A')[:32]}...")
            print(f"Total Documents: {status['total_documents']}")
            print(f"Last Updated: {status.get('created_at')}")
        else:
            print("No documents on server")
            print("Next Document ID: 0")
        
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Server request failed: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)


def cmd_vigilant_status(args):
    """Get vigilant status."""
    try:
        _validate_server_url(args.server)
        session = _create_tls_session()
        response = session.get(f"{args.server}/", timeout=10, verify=True)
        response.raise_for_status()
        status = response.json()
        
        print("\n=== Vigilant Status ===")
        print(f"Status: {status.get('status', 'Unknown')}")
        print(f"Role: {status.get('role', 'Unknown')}")
        print(f"Active User Bans: {status.get('active_bans', 0)}")
        print(f"Active IP Bans: {status.get('active_ip_bans', 0)}")
        print(f"IP Tracking Enabled: {status.get('ip_tracking_enabled', False)}")
        
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Vigilant request failed: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)


def cmd_download(args):
    """Download documents from server and save with fixed directory structure."""
    try:
        _validate_server_url(args.server)
        # Setup fixed directory structure
        BASE_DIR = Path.home() / "deathnote_client"
        DOCS_DIR = BASE_DIR / "pro_documents"  # Encrypted documents
        BUNDLES_DIR = BASE_DIR / "un_bundles"  # Unencrypted bundles
        CACHE_DIR = BASE_DIR / ".cache"
        
        # Create directories if they don't exist
        for directory in [DOCS_DIR, BUNDLES_DIR, CACHE_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Fetch documents from server
        session = _create_tls_session()
        params = {'since_id': args.since_id, 'limit': args.limit}
        response = session.get(
            f"{args.server}/documents",
            params=params,
            timeout=30,
            verify=True
        )
        response.raise_for_status()
        data = response.json()
        
        print(f"\n=== Downloading Documents ===")
        print(f"Fetched {data['total_returned']} documents from server")
        print(f"\nSaving to: {BASE_DIR}")
        
        # Save each document with fixed filename: doc_{id}.json
        for doc in data['documents']:
            doc_id = doc['id']
            
            # Save encrypted document
            encrypted_file = DOCS_DIR / f"doc_{doc_id}.protected.json"
            with open(encrypted_file, 'w') as f:
                json.dump(doc, f, indent=2)
            print(f"  ✓ Saved encrypted: pro_documents/doc_{doc_id}.protected.json")
            
            # If shared_secret provided, also save unencrypted bundle
            if args.shared_secret:
                try:
                    with open(args.shared_secret, 'rb') as f:
                        shared_secret = f.read()
                    
                    # Reconstruct the full protected document from downloaded data
                    protected = {
                        'encrypted_payload': doc['encrypted_payload'],
                        'payload_hash': doc.get('payload_hash'),
                        'payload_signature': doc.get('payload_signature')
                    }
                    bundle = unprotect(protected, shared_secret)
                    
                    bundle_file = BUNDLES_DIR / f"bundle_{doc_id}.json"
                    with open(bundle_file, 'w') as f:
                        json.dump(bundle, f, indent=2)
                    print(f"  ✓ Saved bundle: un_bundles/bundle_{doc_id}.json")
                except Exception as e:
                    print(f"  ⚠ Could not decrypt doc_{doc_id}: {e}")
        
        # Save sync state to cache
        sync_state = {
            'last_document_id': data['documents'][-1]['id'] if data['documents'] else -1,
            'total_documents': data['total_returned'],
            'has_more': data['has_more']
        }
        
        sync_file = CACHE_DIR / 'sync_state.json'
        with open(sync_file, 'w') as f:
            json.dump(sync_state, f, indent=2)
        
        print(f"\n Download complete!")
        print(f"   Encrypted docs: {DOCS_DIR}")
        print(f"   Unencrypted bundles: {BUNDLES_DIR}")
        print(f"   Sync state: {sync_file}")
        print(f"   Has more: {data['has_more']}")
        
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Server request failed: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='DeathNode - Secure Document Format CLI'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # protect command
    parser_protect = subparsers.add_parser('protect', help='Protect a document for peer-to-peer network')
    parser_protect.add_argument('input_file', help='Input JSON document')
    parser_protect.add_argument('private_key', help='Signer private key file (PEM)')
    parser_protect.add_argument('shared_secret', help='Shared secret file for KDF key derivation')
    parser_protect.add_argument('document_id', help='Document ID (0, 1, 2...) or "auto" to fetch from server')
    parser_protect.add_argument('output_file', help='Output protected document')
    parser_protect.add_argument('--prev-hash', help='Previous document hash file for chain verification')
    parser_protect.add_argument('--server', help='Server URL (required if document_id is "auto")')
    
    # unprotect command
    parser_unprotect = subparsers.add_parser('unprotect', help='Unprotect a document')
    parser_unprotect.add_argument('input_file', help='Protected document')
    parser_unprotect.add_argument('shared_secret', help='Shared secret file for KDF key derivation')
    parser_unprotect.add_argument('output_file', help='Output unprotected document')
    parser_unprotect.add_argument('--prev-hash', help='Previous document hash file')
    
    # check command
    parser_check = subparsers.add_parser('check', help='Check unprotected document signature and hashes')
    parser_check.add_argument('input_file', help='Unprotected document (bundle with signature)')
    
    # chain-verify command
    parser_chain = subparsers.add_parser('chain-verify', help='Verify document chain')
    parser_chain.add_argument('protected_dir', help='Directory with protected documents')
    parser_chain.add_argument('shared_secret', help='Shared secret file for KDF key derivation')
    parser_chain.add_argument('--local-docs', help='Directory with local unprotected documents for comparison')
    parser_chain.add_argument('--prev-hash', help='Previous document hash file')
    
    # users command (server interaction)
    parser_users = subparsers.add_parser('users', help='Get list of registered users and their public keys')
    parser_users.add_argument('--server', required=True, help='Server URL')
    
    # upload command (server interaction)
    parser_upload = subparsers.add_parser('upload', help='Upload protected document to server')
    parser_upload.add_argument('protected_file', help='Protected document JSON file')
    parser_upload.add_argument('--server', required=True, help='Server URL (e.g., http://192.168.0.200:6000)')
    
    # status command (server interaction)
    parser_status = subparsers.add_parser('server-status', help='Get server status')
    parser_status.add_argument('--server', required=True, help='Server URL')
    
    # vigilant-status command (vigilant interaction)
    parser_vigilant_status = subparsers.add_parser('vigilant-status', help='Get vigilant status')
    parser_vigilant_status.add_argument('--server', required=True, help='Vigilant URL')
    
    # download command (server interaction)
    parser_download = subparsers.add_parser('download', help='Download documents from server to fixed directory')
    parser_download.add_argument('--server', required=True, help='Server URL')
    parser_download.add_argument('--since-id', type=int, default=0, dest='since_id', help='Download since ID (default: 0)')
    parser_download.add_argument('--limit', type=int, default=100, help='Max documents (default: 100)')
    parser_download.add_argument('--shared-secret', dest='shared_secret', help='Shared secret file to decrypt and save bundles (optional)')
    
    # help command (prints usage)
    subparsers.add_parser('help', help='Show help and usage')
    
    args = parser.parse_args()
    
    # If no command provided, show help
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    # Execute command
    if args.command == 'help':
        parser.print_help()
        sys.exit(0)
    elif args.command == 'protect':
        cmd_protect(args)
    elif args.command == 'unprotect':
        cmd_unprotect(args)
    elif args.command == 'check':
        cmd_check(args)
    elif args.command == 'chain-verify':
        cmd_chain_verify(args)
    elif args.command == 'users':
        cmd_users(args)
    elif args.command == 'upload':
        cmd_upload(args)
    elif args.command == 'server-status':
        cmd_status(args)
    elif args.command == 'vigilant-status':
        cmd_vigilant_status(args)
    elif args.command == 'download':
        cmd_download(args)
    else:
        print(f"ERROR: Unknown command: {args.command}", file=sys.stderr)
        print("Run 'python main.py help' for usage information", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
