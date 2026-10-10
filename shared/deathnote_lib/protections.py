import json
import base64
import os
from typing import Dict, Any, Optional, List
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto_utils import (
    sign_data,
    verify_signature,
    compute_hash,
    compute_chain_hash,
    derive_key_from_secret
)

class ProtectionError(Exception):
    """Base exception for protection operations."""
    pass


def protect(document: Dict[str, Any], private_key_pem: bytes, 
            shared_secret: bytes,
            document_id: int,
            prev_hash: Optional[bytes] = None,
            ) -> Dict[str, Any]:

    try:   
        if 'reporter_pseudonym' in document:
            reporter_pseudonym = document.get('reporter_pseudonym')
        else:
            raise ProtectionError("Document missing 'reporter_pseudonym' field")

        document_json = json.dumps(document, sort_keys=True)
        document_bytes = document_json.encode('utf-8')
        
        doc_hash = compute_hash(document_bytes)
        
        # Each chain_hash depends on previous chain_hash, linking ALL previous documents
        if prev_hash is not None:
            # Use previous document's chain_hash to build on entire history
            chain_hash = compute_chain_hash(prev_hash, document_bytes)
        else:
            # First document - chain from zero hash
            zero_hash = b'\x00' * 32
            chain_hash = compute_chain_hash(zero_hash, document_bytes)
        
        signature = sign_data(doc_hash, private_key_pem)
        
        # Extract signer's public key to include in bundle for verification
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        signer_private_key = serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend()
        )
        signer_public_key_pem = signer_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Bundle document + signature + signer public key + hashes + document_id together for encryption
        bundle = {
            'document': document,
            'signature': base64.b64encode(signature).decode('ascii'),
            'signer_public_key': base64.b64encode(signer_public_key_pem).decode('ascii'),
            'document_hash': base64.b64encode(doc_hash).decode('ascii'),
            'chain_hash': base64.b64encode(chain_hash).decode('ascii')
        }
        bundle_json = json.dumps(bundle, sort_keys=True)
        bundle_bytes = bundle_json.encode('utf-8')
        
        # All peers can derive the same key knowing shared_secret + document_id
        document_id_bytes = str(document_id).encode('utf-8')
        sym_key = derive_key_from_secret(
            shared_secret=shared_secret,
            salt=document_id_bytes,
            info=b'DeathNode-Report-Key-v1'
        )
        
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        # Encrypt bundle with derived AES key (SR1)
        aesgcm = AESGCM(sym_key)
        ciphertext = aesgcm.encrypt(nonce, bundle_bytes, None)
        
        # Create metadata (document_id stored here for KDF)
        metadata = {
            'document_id': document_id,  # Needed outside encryption for KDF
            'algorithm': 'AES-256-GCM',
            'signature_algorithm': 'RSA-PSS-SHA256',
            'kdf_algorithm': 'HKDF-SHA256',
            'protected_at': datetime.utcnow().isoformat() + 'Z',
            'reporter_pseudonym': reporter_pseudonym
        }
        metadata_bytes = json.dumps(metadata, sort_keys=True).encode('utf-8')
        payload_data = metadata_bytes + nonce + ciphertext
        
        # Hash the payload first (more efficient for signing)
        payload_hash = compute_hash(payload_data)
        
        # Sign the hash (standard practice: hash-then-sign)
        payload_signature = sign_data(payload_hash, private_key_pem)

        # Construct protected document (simplified payload)
        protected = {
            'encrypted_payload': {
                'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
                'nonce': base64.b64encode(nonce).decode('ascii'),
                'metadata': metadata
            },
            'payload_hash': base64.b64encode(payload_hash).decode('ascii'),
            'payload_signature': base64.b64encode(payload_signature).decode('ascii')
        }
        
        return protected
        
    except Exception as e:
        raise ProtectionError(f"Failed to protect document: {str(e)}")
    

def check(bundle: Dict[str, Any]) -> Dict[str, Any]:

    try:
        result = {
            'valid': False,
            'checks': {},
            'errors': []
        }
        
        # 1. Validate bundle structure
        required_fields = ['document', 'signature', 'signer_public_key', 'document_hash']
        missing = [f for f in required_fields if f not in bundle]
        if missing:
            result['errors'].append(f"Missing required fields: {', '.join(missing)}")
            return result
        
        # 2. Extract and decode components
        try:
            document = bundle['document']
            signature = base64.b64decode(bundle['signature'])
            signer_public_key_pem = base64.b64decode(bundle['signer_public_key'])
            doc_hash_stored = base64.b64decode(bundle['document_hash'])
        except Exception as e:
            result['errors'].append(f"Failed to decode bundle components: {str(e)}")
            return result
        
        # 3. Serialize document for verification
        document_json = json.dumps(document, sort_keys=True)
        document_bytes = document_json.encode('utf-8')
        
        # 4. Verify document hash first (SR2)
        try:
            doc_hash_computed = compute_hash(document_bytes)
            hash_valid = (doc_hash_computed == doc_hash_stored)
            result['checks']['document_hash'] = hash_valid
            if not hash_valid:
                result['errors'].append("Document hash mismatch - integrity check failed")
        except Exception as e:
            result['checks']['document_hash'] = False
            result['errors'].append(f"Hash verification failed: {str(e)}")
        
        # 5. Verify digital signature against document hash (SR2+SR4)
        try:
            signature_valid = verify_signature(doc_hash_stored, signature, signer_public_key_pem)
            result['checks']['signature'] = signature_valid
            if not signature_valid:
                result['errors'].append("Invalid signature - document may be tampered")
        except Exception as e:
            result['checks']['signature'] = False
            result['errors'].append(f"Signature verification failed: {str(e)}")
        
        # 7. Compute signer fingerprint for identification
        signer_fingerprint = compute_hash(signer_public_key_pem).hex()[:16]
        result['signer_key_fingerprint'] = signer_fingerprint
        
        # 8. Overall validation
        basic_checks = result['checks']['signature'] and result['checks']['document_hash']
        result['valid'] = basic_checks
        
        return result
        
    except Exception as e:
        raise ProtectionError(f"Failed to check bundle: {str(e)}")


def unprotect(protected_document: Dict[str, Any], shared_secret: bytes,
              prev_hash: Optional[bytes] = None) -> Dict[str, Any]:

    try:
        # 1. Extract encrypted components
        envelope = protected_document['encrypted_payload']
        
        ciphertext = base64.b64decode(envelope['ciphertext'])
        nonce = base64.b64decode(envelope['nonce'])
        metadata = envelope.get('metadata', {})

        if 'payload_signature' not in protected_document:
            raise ProtectionError("Missing payload_signature, document may be tampered")
        
        # 2. Get document_id from metadata to derive decryption key
        document_id = metadata.get('document_id')
        if document_id is None:
            raise ProtectionError("Missing document_id in metadata - cannot derive decryption key")
        
        # 3. Derive AES key from shared secret using document_id as salt (same as in protect)
        document_id_bytes = str(document_id).encode('utf-8')
        sym_key = derive_key_from_secret(
            shared_secret=shared_secret,
            salt=document_id_bytes,
            info=b'DeathNode-Report-Key-v1'
        )
        
        # 4. Decrypt bundle with derived AES key
        aesgcm = AESGCM(sym_key)
        bundle_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        bundle_json = bundle_bytes.decode('utf-8')
        bundle = json.loads(bundle_json)

        # 5. Verify outer signature now that we have the public key
        signer_public_key_pem = base64.b64decode(bundle['signer_public_key'])
        if not verify_payload_signature(protected_document, signer_public_key_pem):
            raise ProtectionError("Outer signature verification failed - envelope may be tampered")

        # Return the decrypted bundle (verification done by check())
        return bundle
        
    except ProtectionError:
        raise
    except Exception as e:
        raise ProtectionError(f"Failed to unprotect document: {str(e)}")
    

def verify_payload_signature(protected_document: Dict[str, Any], public_key_pem: bytes) -> bool:
    try:
        encrypted_payload = protected_document['encrypted_payload']
        metadata = encrypted_payload.get('metadata', {})
        nonce = base64.b64decode(encrypted_payload.get('nonce', ''))
        ciphertext = base64.b64decode(encrypted_payload.get('ciphertext', ''))
        
        payload_hash_stored = base64.b64decode(protected_document.get('payload_hash', ''))
        signature_bytes = base64.b64decode(protected_document.get('payload_signature', ''))

        metadata_bytes = json.dumps(metadata, sort_keys=True).encode('utf-8')
        payload_data = metadata_bytes + nonce + ciphertext
        payload_hash_computed = compute_hash(payload_data)
        
        if payload_hash_computed != payload_hash_stored:
            return False

        return verify_signature(payload_hash_stored, signature_bytes, public_key_pem)
    except Exception:
        return False


def verify_chain(protected_documents: List[Dict[str, Any]], 
                 shared_secret: bytes,
                 local_documents: Optional[List[Dict[str, Any]]] = None,
                 prev_hash: Optional[bytes] = None) -> Dict[str, Any]:

    result = {
        'valid': True,
        'total_documents': len(protected_documents),
        'documents': [],
        'tampering_detected': False,
        'duplicate_content_detected': False,
        'errors': []
    }
    # Track content hashes to detect duplicate content 
    seen_content_hashes = {}
    
    # Create lookup for local documents by ID (local_documents are unencrypted bundles)
    local_bundles_by_id = {}
    if local_documents:
        for i, local_bundle in enumerate(local_documents):
            # Local bundles are saved as bundle_{doc_id}.json, so doc_id should be i+1
            doc_id = i + 1  # bundle_1.json -> doc_id=1, bundle_2.json -> doc_id=2, etc.
            local_bundles_by_id[doc_id] = local_bundle
    
    for i, server_doc in enumerate(protected_documents):
        doc_id = None
        try:
            # Extract document_id from metadata
            metadata = server_doc.get('encrypted_payload', {}).get('metadata', {})
            doc_id = metadata.get('document_id')
            
            if doc_id is None:
                raise ProtectionError("Missing document_id in metadata")
            
            # Verify document_id matches expected position
            if doc_id != (i + 1):
                raise ProtectionError(f"Document ID mismatch: expected {i + 1}, got {doc_id}")
            
            # Decrypt server document
            server_bundle = unprotect(server_doc, shared_secret)
            
            # Verify document using check() (signature, doc hash, chain hash)
            check_result = check(server_bundle)
            if not check_result['valid']:
                raise ProtectionError(
                    f"Document validation failed: {', '.join(check_result.get('errors', ['Unknown error']))}"
                )
            
            server_chain_hash_stored = base64.b64decode(server_bundle['chain_hash'])
            
            # Check if we had this document locally (tampering detection)
            is_old_document = doc_id in local_bundles_by_id
            tampering = False
            
            # Check for duplicate content
            document = server_bundle['document']
            document_json = json.dumps(document, sort_keys=True)
            document_bytes = document_json.encode('utf-8')
            content_hash = compute_hash(document_bytes).hex()

            
            duplicate_content = False
            if content_hash in seen_content_hashes:
                duplicate_content = True
                result['duplicate_content_detected'] = True
                previous_doc_id = seen_content_hashes[content_hash]
                print(f"[WARNING] Document {doc_id} has identical content to document {previous_doc_id}", flush=True)
            else:
                seen_content_hashes[content_hash] = doc_id
            
            if is_old_document:
                # OLD DOCUMENT: Compare chain_hash with local version to detect tampering
                local_bundle = local_bundles_by_id[doc_id]
                local_chain_hash = base64.b64decode(local_bundle['chain_hash'])
                
                if server_chain_hash_stored != local_chain_hash:
                    tampering = True
                    result['tampering_detected'] = True
                    raise ProtectionError(
                        f"TAMPERING DETECTED: chain_hash changed since last fetch! "
                        f"Local: {base64.b64encode(local_chain_hash).decode()[:32]}... "
                        f"Server: {base64.b64encode(server_chain_hash_stored).decode()[:32]}..."
                    )
                
            else:
                # NEW DOCUMENT: Verify chain_hash by recalculating it
                # Recalculate chain_hash from prev_hash + current plaintext
                if prev_hash is not None:
                    chain_hash_computed = compute_chain_hash(prev_hash, document_bytes)
                else:
                    # First document (no prev_hash) - chain from zero hash
                    zero_hash = b'\x00' * 32
                    chain_hash_computed = compute_chain_hash(zero_hash, document_bytes)
                
                # Compare computed vs stored
                if chain_hash_computed != server_chain_hash_stored:
                    raise ProtectionError(
                        f"Chain hash verification FAILED for new document {doc_id}! "
                        f"Computed: {base64.b64encode(chain_hash_computed).decode()[:32]}... "
                        f"Stored: {base64.b64encode(server_chain_hash_stored).decode()[:32]}..."
                    )
            
            # Save whether this was the first document (before updating prev_hash)
            was_first_document = (prev_hash is None)
            
            # Update prev_hash for next iteration (use chain_hash to maintain blockchain-style chain)
            prev_hash = server_chain_hash_stored
            
            # All checks passed
            doc_result = {
                'valid': True,
                'document_id': doc_id,
                'is_new': not is_old_document,
                'tampering': tampering,
                'duplicate_content': duplicate_content,
                'signer': check_result.get('signer_key_fingerprint'),
                'checks': {
                    'document_id': True,
                    'decryption': True,
                    'signature': check_result['checks'].get('signature', True),
                    'document_hash': check_result['checks'].get('document_hash', True),
                    'chain_hash': 'first_document' if was_first_document else True,
                    'tampering_check': 'passed' if is_old_document else 'new_document',
                    'duplicate_content_check': 'duplicate' if duplicate_content else 'unique'
                },
                'errors': [],
                'warnings': [f"Duplicate content (same as document {seen_content_hashes[content_hash]})"] if duplicate_content else []
            }
            
        except ProtectionError as e:
            doc_result = {
                'valid': False,
                'document_id': doc_id,
                'is_new': doc_id not in local_bundles_by_id if doc_id else None,
                'tampering': 'TAMPERING' in str(e),
                'checks': {
                    'document_id': False if 'ID mismatch' in str(e) else True,
                    'decryption': False,
                    'signature': False,
                    'document_hash': False,
                    'chain_hash': False,
                    'tampering_check': 'FAILED' if 'TAMPERING' in str(e) else 'error'
                },
                'errors': [str(e)]
            }
        
        result['documents'].append({
            'index': i,
            'document_id': doc_id,
            'valid': doc_result['valid'],
            'is_new': doc_result.get('is_new'),
            'tampering': doc_result.get('tampering'),
            'duplicate_content': doc_result.get('duplicate_content', False),
            'checks': doc_result['checks'],
            'errors': doc_result.get('errors', []),
            'warnings': doc_result.get('warnings', [])
        })
        
        if not doc_result['valid']:
            result['valid'] = False
            result['errors'].append(f"Document {i} (ID={doc_id}) failed verification")
    
    return result


def get_chain_hash(protected_document: Dict[str, Any], shared_secret: bytes) -> bytes:
    """Get chain hash from encrypted bundle (to use as prev_hash for next document)."""
    envelope = protected_document['encrypted_payload']
    
    ciphertext = base64.b64decode(envelope['ciphertext'])
    nonce = base64.b64decode(envelope['nonce'])
    metadata = envelope.get('metadata', {})
    
    # Get document_id to derive decryption key
    document_id = metadata.get('document_id')
    if document_id is None:
        raise ProtectionError("Missing document_id in metadata")
    
    # Derive AES key using document_id as salt
    document_id_bytes = str(document_id).encode('utf-8')
    sym_key = derive_key_from_secret(
        shared_secret=shared_secret,
        salt=document_id_bytes,
        info=b'DeathNode-Report-Key-v1'
    )
    
    # Decrypt bundle
    aesgcm = AESGCM(sym_key)
    bundle_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    bundle_json = bundle_bytes.decode('utf-8')
    bundle = json.loads(bundle_json)
    
    # Return chain hash (this becomes prev_hash for next document)
    return base64.b64decode(bundle['chain_hash'])