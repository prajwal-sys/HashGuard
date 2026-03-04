"""
Cryptographic Engine Module for Forensic PKI Tool

This module handles:
- SHA-256 hashing of evidence and metadata
- ECDSA digital signature generation
- Signature verification
- Combined hash computation
"""

import hashlib
import json
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography import x509


class CryptoEngine:
    """
    Cryptographic operations engine for forensic evidence integrity.
    
    Implements SHA-256 hashing and ECDSA signature operations
    following forensic best practices.
    """
    
    # Hash algorithm for all operations
    HASH_ALGORITHM = "SHA256"
    HASH_FUNCTION = hashlib.sha256
    
    def __init__(self):
        """Initialize the cryptographic engine."""
        pass
    
    def hash_file(self, file_path: str, chunk_size: int = 8192) -> str:
        """
        Compute SHA-256 hash of a file.
        
        Uses streaming to handle large files efficiently without
        loading entire file into memory.
        
        Args:
            file_path: Path to the file to hash
            chunk_size: Size of chunks to read (default 8KB)
            
        Returns:
            Hexadecimal hash string
            
        Raises:
            FileNotFoundError: If file doesn't exist
            IOError: If file cannot be read
        """
        sha256_hash = self.HASH_FUNCTION()
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
        except FileNotFoundError:
            raise FileNotFoundError(f"Evidence file not found: {file_path}")
        except Exception as e:
            raise IOError(f"Error reading file: {e}")
        
        return sha256_hash.hexdigest()
    
    def hash_bytes(self, data: bytes) -> str:
        """
        Compute SHA-256 hash of byte data.
        
        Args:
            data: Byte data to hash
            
        Returns:
            Hexadecimal hash string
        """
        sha256_hash = self.HASH_FUNCTION(data)
        return sha256_hash.hexdigest()
    
    def hash_metadata(self, metadata: dict) -> str:
        """
        Compute SHA-256 hash of metadata dictionary.
        
        Metadata is canonicalized to JSON with sorted keys to ensure
        reproducible hashing regardless of dictionary ordering.
        
        Args:
            metadata: Dictionary containing evidence metadata
            
        Returns:
            Hexadecimal hash string
        """
        # Canonicalize metadata to JSON with sorted keys
        # This ensures reproducible hashing
        metadata_json = json.dumps(
            metadata,
            sort_keys=True,
            separators=(',', ':'),  # Compact format
            ensure_ascii=True
        )
        
        # Hash the JSON string
        metadata_bytes = metadata_json.encode('utf-8')
        return self.hash_bytes(metadata_bytes)
    
    def compute_combined_hash(
        self,
        evidence_hash: str,
        metadata_hash: str
    ) -> str:
        """
        Compute combined hash from evidence and metadata hashes.
        
        The combined hash is computed by:
        1. Concatenating evidence_hash and metadata_hash
        2. Hashing the concatenation with SHA-256
        
        This creates a single digest representing both evidence and metadata.
        
        Args:
            evidence_hash: Hexadecimal hash of evidence file
            metadata_hash: Hexadecimal hash of metadata
            
        Returns:
            Hexadecimal combined hash string
        """
        # Concatenate hashes
        combined = evidence_hash + metadata_hash
        
        # Hash the concatenation
        combined_bytes = combined.encode('utf-8')
        return self.hash_bytes(combined_bytes)
    
    def sign_hash(
        self,
        hash_value: str,
        private_key: ec.EllipticCurvePrivateKey
    ) -> bytes:
        """
        Create digital signature of a hash using ECDSA.
        
        Signs the hash value with the investigator's private key,
        providing authentication and non-repudiation.
        
        Args:
            hash_value: Hexadecimal hash string to sign
            private_key: ECC private key for signing
            
        Returns:
            Digital signature as bytes
            
        Raises:
            ValueError: If hash value is invalid
        """
        if not hash_value or not isinstance(hash_value, str):
            raise ValueError("Invalid hash value")
        
        # Convert hex hash to bytes
        hash_bytes = hash_value.encode('utf-8')
        
        # Sign using ECDSA with SHA-256
        signature = private_key.sign(
            hash_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        
        return signature
    
    def verify_signature(
        self,
        hash_value: str,
        signature: bytes,
        certificate: x509.Certificate
    ) -> bool:
        """
        Verify digital signature of a hash using certificate's public key.
        
        Args:
            hash_value: Hexadecimal hash string that was signed
            signature: Digital signature bytes
            certificate: X.509 certificate containing public key
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Extract public key from certificate
            public_key = certificate.public_key()
            
            # Convert hex hash to bytes
            hash_bytes = hash_value.encode('utf-8')
            
            # Verify signature
            public_key.verify(
                signature,
                hash_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            
            return True
            
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"[-] Signature verification error: {e}")
            return False
    
    def verify_file_hash(
        self,
        file_path: str,
        expected_hash: str
    ) -> bool:
        """
        Verify that a file's hash matches the expected value.
        
        Args:
            file_path: Path to the file to verify
            expected_hash: Expected hexadecimal hash value
            
        Returns:
            True if hash matches, False otherwise
        """
        try:
            computed_hash = self.hash_file(file_path)
            return computed_hash.lower() == expected_hash.lower()
        except Exception as e:
            print(f"[-] Hash verification error: {e}")
            return False
    
    def create_evidence_seal(
        self,
        evidence_hash: str,
        metadata_hash: str,
        private_key: ec.EllipticCurvePrivateKey
    ) -> Tuple[str, bytes]:
        """
        Create complete evidence seal (combined hash + signature).
        
        This is the main sealing operation that:
        1. Computes combined hash
        2. Signs the combined hash
        
        Args:
            evidence_hash: Hash of evidence file
            metadata_hash: Hash of metadata
            private_key: Investigator's private key
            
        Returns:
            Tuple of (combined_hash, signature)
        """
        # Compute combined hash
        combined_hash = self.compute_combined_hash(
            evidence_hash,
            metadata_hash
        )
        
        # Sign combined hash
        signature = self.sign_hash(combined_hash, private_key)
        
        return combined_hash, signature
    
    def verify_evidence_seal(
        self,
        evidence_hash: str,
        metadata_hash: str,
        expected_combined_hash: str,
        signature: bytes,
        certificate: x509.Certificate
    ) -> Tuple[bool, str]:
        """
        Verify complete evidence seal.
        
        Performs comprehensive verification:
        1. Recomputes combined hash
        2. Verifies it matches expected value
        3. Verifies digital signature
        
        Args:
            evidence_hash: Computed hash of evidence file
            metadata_hash: Computed hash of metadata
            expected_combined_hash: Expected combined hash value
            signature: Digital signature
            certificate: Investigator's certificate
            
        Returns:
            Tuple of (is_valid, message)
        """
        # Recompute combined hash
        computed_combined_hash = self.compute_combined_hash(
            evidence_hash,
            metadata_hash
        )
        
        # Verify combined hash matches
        if computed_combined_hash != expected_combined_hash:
            return False, (
                "Combined hash mismatch - evidence or metadata has been altered"
            )
        
        # Verify signature
        signature_valid = self.verify_signature(
            computed_combined_hash,
            signature,
            certificate
        )
        
        if not signature_valid:
            return False, "Invalid signature - authenticity cannot be verified"
        
        return True, "Evidence seal verified successfully"


# Example usage and testing
if __name__ == "__main__":
    import tempfile
    import os
    from key_management import InvestigatorKeyManager
    
    print("=== Forensic Cryptographic Engine Module ===\n")
    
    # Initialize components
    crypto = CryptoEngine()
    km = InvestigatorKeyManager()
    
    # Create test evidence file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("This is confidential evidence for case #12345")
        test_file = f.name
    
    try:
        print(f"[*] Test evidence file: {test_file}")
        
        # Hash evidence file
        print("\n[*] Hashing evidence file...")
        evidence_hash = crypto.hash_file(test_file)
        print(f"[+] Evidence hash: {evidence_hash}")
        
        # Create test metadata
        metadata = {
            "case_id": "CASE-2025-001",
            "investigator_id": "INV001",
            "timestamp": "2025-02-08T12:00:00Z",
            "hash_algorithm": "SHA256"
        }
        
        print("\n[*] Hashing metadata...")
        metadata_hash = crypto.hash_metadata(metadata)
        print(f"[+] Metadata hash: {metadata_hash}")
        
        # Compute combined hash
        print("\n[*] Computing combined hash...")
        combined_hash = crypto.compute_combined_hash(evidence_hash, metadata_hash)
        print(f"[+] Combined hash: {combined_hash}")
        
        # Test with investigator keys (if exists)
        try:
            print("\n[*] Testing signature operations...")
            private_key = km.load_private_key("INV001", "SecurePassword123!")
            certificate = km.load_certificate("INV001")
            
            # Sign combined hash
            signature = crypto.sign_hash(combined_hash, private_key)
            print(f"[+] Signature created: {len(signature)} bytes")
            
            # Verify signature
            is_valid = crypto.verify_signature(combined_hash, signature, certificate)
            print(f"[+] Signature verification: {is_valid}")
            
            # Test full seal verification
            seal_valid, message = crypto.verify_evidence_seal(
                evidence_hash,
                metadata_hash,
                combined_hash,
                signature,
                certificate
            )
            print(f"[+] Evidence seal verification: {seal_valid} - {message}")
            
        except FileNotFoundError:
            print("[-] Investigator keys not found (run key_management.py first)")
    
    finally:
        # Cleanup
        os.unlink(test_file)
        print("\n[*] Test file cleaned up")