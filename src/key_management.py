"""
Key Management Module for Forensic PKI Tool

This module handles:
- ECC key pair generation (ECDSA P-256)
- Self-signed certificate generation
- Secure key storage (PEM format with password encryption)
- Certificate loading and validation
"""

import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


class InvestigatorKeyManager:
    """
    Manages cryptographic keys and certificates for forensic investigators.
    
    Uses ECC (ECDSA) with P-256 curve for asymmetric operations.
    Private keys are stored encrypted with password protection.
    """
    
    def __init__(self, data_dir: str = "data/investigators"):
        """
        Initialize the key manager.
        
        Args:
            data_dir: Directory to store investigator keys and certificates
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_investigator_keypair(
        self,
        investigator_id: str,
        password: str,
        organization: str = "Digital Forensics Lab",
        country: str = "US",
        validity_days: int = 365
    ) -> Tuple[str, str]:
        """
        Generate ECC key pair and self-signed certificate for an investigator.
        
        Args:
            investigator_id: Unique identifier for the investigator
            password: Password to encrypt the private key
            organization: Organization name for certificate
            country: Country code (ISO 3166-1 alpha-2)
            validity_days: Certificate validity period in days
            
        Returns:
            Tuple of (private_key_path, certificate_path)
            
        Raises:
            ValueError: If investigator already exists or invalid parameters
        """
        # Validate inputs
        if not investigator_id or not password:
            raise ValueError("Investigator ID and password are required")
        
        investigator_dir = self.data_dir / investigator_id
        private_key_path = investigator_dir / "private_key.pem"
        certificate_path = investigator_dir / "certificate.crt"
        
        # Check if investigator already exists
        if investigator_dir.exists():
            raise ValueError(
                f"Investigator '{investigator_id}' already exists. "
                f"Delete the directory first if regeneration is needed."
            )
        
        investigator_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"[*] Generating ECC key pair for investigator: {investigator_id}")
        
        # Generate ECC private key using P-256 curve (NIST recommended)
        private_key = ec.generate_private_key(
            ec.SECP256R1(),  # P-256 curve
            default_backend()
        )
        
        # Extract public key
        public_key = private_key.public_key()
        
        print("[*] Generating self-signed X.509 certificate")
        
        # Build certificate subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, f"Investigator {investigator_id}"),
            x509.NameAttribute(NameOID.USER_ID, investigator_id),
        ])
        
        # Generate certificate
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            # Add extensions for forensic use
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=True,  # Non-repudiation
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            # Sign with SHA-256
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        
        print("[*] Encrypting and saving private key")
        
        # Serialize and encrypt private key with password
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode('utf-8')
            )
        )
        
        # Write private key to file with restricted permissions
        with open(private_key_path, 'wb') as f:
            f.write(private_key_pem)
        os.chmod(private_key_path, 0o600)  # Read/write for owner only
        
        print("[*] Saving certificate")
        
        # Serialize and save certificate
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        with open(certificate_path, 'wb') as f:
            f.write(certificate_pem)
        
        print(f"[+] Successfully created investigator '{investigator_id}'")
        print(f"    Private key: {private_key_path}")
        print(f"    Certificate: {certificate_path}")
        print(f"    Certificate valid until: {certificate.not_valid_after}")
        
        return str(private_key_path), str(certificate_path)
    
    def load_private_key(
        self,
        investigator_id: str,
        password: str
    ) -> ec.EllipticCurvePrivateKey:
        """
        Load and decrypt an investigator's private key.
        
        Args:
            investigator_id: Unique identifier for the investigator
            password: Password to decrypt the private key
            
        Returns:
            Loaded ECC private key object
            
        Raises:
            FileNotFoundError: If investigator doesn't exist
            ValueError: If password is incorrect
        """
        private_key_path = self.data_dir / investigator_id / "private_key.pem"
        
        if not private_key_path.exists():
            raise FileNotFoundError(
                f"Investigator '{investigator_id}' not found. "
                f"Run 'init-investigator' first."
            )
        
        with open(private_key_path, 'rb') as f:
            private_key_pem = f.read()
        
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=password.encode('utf-8'),
                backend=default_backend()
            )
        except ValueError:
            raise ValueError("Incorrect password for private key")
        
        return private_key
    
    def load_certificate(self, investigator_id: str) -> x509.Certificate:
        """
        Load an investigator's certificate.
        
        Args:
            investigator_id: Unique identifier for the investigator
            
        Returns:
            Loaded X.509 certificate object
            
        Raises:
            FileNotFoundError: If certificate doesn't exist
        """
        certificate_path = self.data_dir / investigator_id / "certificate.crt"
        
        if not certificate_path.exists():
            raise FileNotFoundError(
                f"Certificate for investigator '{investigator_id}' not found"
            )
        
        with open(certificate_path, 'rb') as f:
            certificate_pem = f.read()
        
        certificate = x509.load_pem_x509_certificate(
            certificate_pem,
            default_backend()
        )
        
        return certificate
    
    def validate_certificate(
        self,
        certificate: x509.Certificate,
        check_expiry: bool = True
    ) -> Tuple[bool, str]:
        """
        Validate a certificate for forensic use.
        
        Args:
            certificate: X.509 certificate to validate
            check_expiry: Whether to check if certificate is expired
            
        Returns:
            Tuple of (is_valid, message)
        """
        current_time = datetime.utcnow()
        
        # Check certificate validity period
        if check_expiry:
            if current_time < certificate.not_valid_before:
                return False, "Certificate not yet valid"
            
            if current_time > certificate.not_valid_after:
                return False, f"Certificate expired on {certificate.not_valid_after}"
        
        # Check for required key usage
        try:
            key_usage = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.KEY_USAGE
            ).value
            
            if not key_usage.digital_signature:
                return False, "Certificate missing digital_signature key usage"
            
            if not key_usage.content_commitment:
                return False, "Certificate missing non-repudiation key usage"
                
        except x509.ExtensionNotFound:
            return False, "Certificate missing KEY_USAGE extension"
        
        return True, "Certificate is valid"
    
    def get_investigator_id_from_certificate(
        self,
        certificate: x509.Certificate
    ) -> Optional[str]:
        """
        Extract investigator ID from certificate USER_ID field.
        
        Args:
            certificate: X.509 certificate
            
        Returns:
            Investigator ID or None if not found
        """
        try:
            for attribute in certificate.subject:
                if attribute.oid == NameOID.USER_ID:
                    return attribute.value
        except Exception:
            pass
        
        return None
    
    def list_investigators(self) -> list:
        """
        List all registered investigators.
        
        Returns:
            List of investigator IDs
        """
        if not self.data_dir.exists():
            return []
        
        investigators = []
        for item in self.data_dir.iterdir():
            if item.is_dir() and (item / "certificate.crt").exists():
                investigators.append(item.name)
        
        return sorted(investigators)


# Example usage and testing
if __name__ == "__main__":
    print("=== Forensic PKI Key Management Module ===\n")
    
    # Initialize key manager
    km = InvestigatorKeyManager()
    
    # Generate test investigator
    try:
        priv_path, cert_path = km.generate_investigator_keypair(
            investigator_id="INV001",
            password="SecurePassword123!",
            organization="Digital Forensics Lab",
            country="US"
        )
        
        print("\n[*] Testing key loading...")
        
        # Load private key
        private_key = km.load_private_key("INV001", "SecurePassword123!")
        print(f"[+] Private key loaded: {type(private_key)}")
        
        # Load certificate
        certificate = km.load_certificate("INV001")
        print(f"[+] Certificate loaded: {certificate.subject}")
        
        # Validate certificate
        is_valid, message = km.validate_certificate(certificate)
        print(f"[+] Certificate validation: {is_valid} - {message}")
        
        # Extract investigator ID
        inv_id = km.get_investigator_id_from_certificate(certificate)
        print(f"[+] Extracted investigator ID: {inv_id}")
        
        # List investigators
        investigators = km.list_investigators()
        print(f"[+] Registered investigators: {investigators}")
        
    except ValueError as e:
        print(f"[-] Error: {e}")