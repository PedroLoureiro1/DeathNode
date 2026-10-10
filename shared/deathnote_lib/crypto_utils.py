from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Create digital signature using RSA-PSS.
    
    Args:
        data: Data to sign
        private_key_pem: Private key in PEM format
    
    Returns:
        Digital signature
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verify digital signature using RSA-PSS.
    
    Args:
        data: Original data
        signature: Signature to verify
        public_key_pem: Public key in PEM format
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def compute_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of data.
    
    Args:
        data: Data to hash
    
    Returns:
        SHA-256 hash digest
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()


def compute_chain_hash(prev_hash: bytes, current_data: bytes) -> bytes:
    """
    Compute chained hash (for detecting missing/reordered reports).
    
    Args:
        prev_hash: Hash of previous element in chain
        current_data: Current element data
    
    Returns:
        Hash of (prev_hash + current_data)
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(prev_hash)
    digest.update(current_data)
    return digest.finalize()


def derive_key_from_secret(shared_secret: bytes, salt: bytes, info: bytes = b'') -> bytes:
    """
    Derive AES key from shared secret using HKDF (HMAC-based KDF).
    
    Uses HKDF (HMAC-based Key Derivation Function) to derive a cryptographic
    key from a shared secret. This allows all nodes with the same shared secret
    to derive the same AES key for a specific report using report-specific salt.
    
    Args:
        shared_secret: Pre-shared secret known by all authorized nodes
        salt: Report-specific salt (e.g., nonce or report ID) for key diversity
        info: Optional context information (e.g., "DeathNode-AES-Key")
    
    Returns:
        256-bit AES key derived from the shared secret
    
    Example:
        # All nodes know shared_secret
        # Each report has unique salt (e.g., nonce)
        aes_key = derive_key_from_secret(shared_secret, nonce, b"DeathNode-Report-Key")
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        info=info,
        backend=default_backend()
    )
    
    return hkdf.derive(shared_secret)
