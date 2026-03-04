"""
Evidence Packaging Module for Forensic PKI Tool

This module handles:
- Evidence bag folder creation
- File organization and copying
- Evidence bag validation
- Evidence extraction and verification
"""

import os
import shutil
from pathlib import Path
from typing import Dict, Tuple, Optional
from datetime import datetime


class EvidencePackager:
    """
    Manages forensic evidence bag packaging and structure.
    
    Evidence bags contain:
    - Original evidence file
    - Metadata (JSON)
    - Combined hash
    - Digital signature
    - Investigator certificate
    """
    
    # Standard evidence bag structure
    EVIDENCE_FILENAME = "evidence_file"
    METADATA_FILENAME = "metadata.json"
    COMBINED_HASH_FILENAME = "combined.hash"
    SIGNATURE_FILENAME = "signature.sig"
    CERTIFICATE_FILENAME = "investigator.crt"
    
    def __init__(self, output_dir: str = "evidence_bags"):
        """
        Initialize the evidence packager.
        
        Args:
            output_dir: Base directory for evidence bags
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_bag_name(self, case_id: str, evidence_filename: str) -> str:
        """
        Generate unique evidence bag folder name.
        
        Format: {case_id}_{evidence_name}_{timestamp}
        
        Args:
            case_id: Case identifier
            evidence_filename: Original evidence filename
            
        Returns:
            Evidence bag folder name
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Clean evidence filename for directory name
        clean_name = Path(evidence_filename).stem
        clean_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in clean_name)
        
        bag_name = f"{case_id}_{clean_name}_{timestamp}"
        
        return bag_name
    
    def create_evidence_bag(
        self,
        case_id: str,
        evidence_path: str,
        metadata: Dict,
        combined_hash: str,
        signature: bytes,
        certificate_path: str,
        bag_name: Optional[str] = None
    ) -> str:
        """
        Create complete evidence bag with all required components.
        
        Args:
            case_id: Case identifier
            evidence_path: Path to original evidence file
            metadata: Evidence metadata dictionary
            combined_hash: Combined hash of evidence and metadata
            signature: Digital signature bytes
            certificate_path: Path to investigator certificate
            bag_name: Optional custom bag name (auto-generated if None)
            
        Returns:
            Path to created evidence bag directory
            
        Raises:
            FileNotFoundError: If evidence or certificate not found
            IOError: If bag creation fails
        """
        # Validate inputs
        if not os.path.exists(evidence_path):
            raise FileNotFoundError(f"Evidence file not found: {evidence_path}")
        
        if not os.path.exists(certificate_path):
            raise FileNotFoundError(f"Certificate not found: {certificate_path}")
        
        # Generate bag name if not provided
        if bag_name is None:
            evidence_filename = Path(evidence_path).name
            bag_name = self.generate_bag_name(case_id, evidence_filename)
        
        # Create bag directory
        bag_path = self.output_dir / bag_name
        
        if bag_path.exists():
            raise IOError(f"Evidence bag already exists: {bag_path}")
        
        try:
            bag_path.mkdir(parents=True, exist_ok=False)
            print(f"[*] Creating evidence bag: {bag_path}")
            
            # Copy evidence file
            evidence_dest = bag_path / self.EVIDENCE_FILENAME
            shutil.copy2(evidence_path, evidence_dest)
            print(f"[+] Evidence file copied")
            
            # Save metadata
            from evidence_processor import EvidenceProcessor
            processor = EvidenceProcessor()
            metadata_dest = bag_path / self.METADATA_FILENAME
            processor.save_metadata(metadata, str(metadata_dest))
            print(f"[+] Metadata saved")
            
            # Save combined hash
            combined_hash_dest = bag_path / self.COMBINED_HASH_FILENAME
            with open(combined_hash_dest, 'w') as f:
                f.write(combined_hash)
            print(f"[+] Combined hash saved")
            
            # Save signature
            signature_dest = bag_path / self.SIGNATURE_FILENAME
            with open(signature_dest, 'wb') as f:
                f.write(signature)
            print(f"[+] Digital signature saved")
            
            # Copy certificate
            certificate_dest = bag_path / self.CERTIFICATE_FILENAME
            shutil.copy2(certificate_path, certificate_dest)
            print(f"[+] Investigator certificate copied")
            
            # Create manifest file for additional integrity
            self._create_manifest(bag_path)
            print(f"[+] Manifest created")
            
            print(f"\n[+] Evidence bag created successfully: {bag_path}")
            
            return str(bag_path)
            
        except Exception as e:
            # Cleanup on failure
            if bag_path.exists():
                shutil.rmtree(bag_path)
            raise IOError(f"Failed to create evidence bag: {e}")
    
    def _create_manifest(self, bag_path: Path) -> None:
        """
        Create manifest file listing all bag contents.
        
        Args:
            bag_path: Path to evidence bag directory
        """
        manifest_path = bag_path / "MANIFEST.txt"
        
        with open(manifest_path, 'w') as f:
            f.write("FORENSIC EVIDENCE BAG MANIFEST\n")
            f.write("="*60 + "\n\n")
            f.write(f"Bag Created: {datetime.now().isoformat()}\n")
            f.write(f"Bag Location: {bag_path.absolute()}\n\n")
            f.write("Contents:\n")
            f.write("-"*60 + "\n")
            
            # List all files with sizes
            for item in sorted(bag_path.iterdir()):
                if item.is_file() and item.name != "MANIFEST.txt":
                    size = item.stat().st_size
                    f.write(f"  {item.name:<30} {size:>10,} bytes\n")
            
            f.write("\n" + "="*60 + "\n")
    
    def validate_bag_structure(self, bag_path: str) -> Tuple[bool, str]:
        """
        Validate evidence bag has correct structure and all required files.
        
        Args:
            bag_path: Path to evidence bag directory
            
        Returns:
            Tuple of (is_valid, message)
        """
        bag = Path(bag_path)
        
        if not bag.exists():
            return False, f"Evidence bag not found: {bag_path}"
        
        if not bag.is_dir():
            return False, f"Not a directory: {bag_path}"
        
        # Check for required files
        required_files = [
            self.EVIDENCE_FILENAME,
            self.METADATA_FILENAME,
            self.COMBINED_HASH_FILENAME,
            self.SIGNATURE_FILENAME,
            self.CERTIFICATE_FILENAME
        ]
        
        missing_files = []
        for filename in required_files:
            file_path = bag / filename
            if not file_path.exists():
                missing_files.append(filename)
        
        if missing_files:
            return False, f"Missing files: {', '.join(missing_files)}"
        
        return True, "Evidence bag structure is valid"
    
    def load_evidence_bag(self, bag_path: str) -> Dict[str, any]:
        """
        Load all components from evidence bag.
        
        Args:
            bag_path: Path to evidence bag directory
            
        Returns:
            Dictionary containing all bag components
            
        Raises:
            FileNotFoundError: If bag or required files not found
            ValueError: If bag structure is invalid
        """
        # Validate bag structure
        is_valid, message = self.validate_bag_structure(bag_path)
        if not is_valid:
            raise ValueError(f"Invalid evidence bag: {message}")
        
        bag = Path(bag_path)
        
        # Load metadata
        from evidence_processor import EvidenceProcessor
        processor = EvidenceProcessor()
        metadata_path = bag / self.METADATA_FILENAME
        metadata = processor.load_metadata(str(metadata_path))
        
        # Load combined hash
        combined_hash_path = bag / self.COMBINED_HASH_FILENAME
        with open(combined_hash_path, 'r') as f:
            combined_hash = f.read().strip()
        
        # Load signature
        signature_path = bag / self.SIGNATURE_FILENAME
        with open(signature_path, 'rb') as f:
            signature = f.read()
        
        # Load certificate
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        certificate_path = bag / self.CERTIFICATE_FILENAME
        with open(certificate_path, 'rb') as f:
            certificate_pem = f.read()
        certificate = x509.load_pem_x509_certificate(
            certificate_pem,
            default_backend()
        )
        
        # Evidence file path (not loaded into memory)
        evidence_file_path = str(bag / self.EVIDENCE_FILENAME)
        
        return {
            "bag_path": str(bag_path),
            "evidence_file_path": evidence_file_path,
            "metadata": metadata,
            "combined_hash": combined_hash,
            "signature": signature,
            "certificate": certificate
        }
    
    def display_bag_info(self, bag_path: str) -> None:
        """
        Display information about an evidence bag.
        
        Args:
            bag_path: Path to evidence bag directory
        """
        try:
            bag_data = self.load_evidence_bag(bag_path)
            
            print("\n" + "="*60)
            print("EVIDENCE BAG INFORMATION")
            print("="*60)
            
            print(f"\nBag Location: {bag_data['bag_path']}")
            
            metadata = bag_data['metadata']
            print(f"\nCase ID: {metadata.get('case_id', 'N/A')}")
            print(f"Investigator: {metadata.get('investigator_id', 'N/A')}")
            print(f"Sealed: {metadata.get('seal_timestamp', 'N/A')}")
            
            if 'evidence' in metadata:
                evidence = metadata['evidence']
                print(f"\nEvidence File: {evidence.get('filename', 'N/A')}")
                print(f"Size: {evidence.get('size_bytes', 0):,} bytes")
                print(f"Description: {evidence.get('description', 'N/A')}")
            
            print(f"\nCombined Hash: {bag_data['combined_hash']}")
            print(f"Signature: {len(bag_data['signature'])} bytes")
            
            # Certificate info
            cert = bag_data['certificate']
            print(f"\nCertificate:")
            print(f"  Subject: {cert.subject.rfc4514_string()}")
            print(f"  Valid Until: {cert.not_valid_after}")
            
            print("\n" + "="*60 + "\n")
            
        except Exception as e:
            print(f"[-] Error loading bag info: {e}")
    
    def list_evidence_bags(self) -> list:
        """
        List all evidence bags in the output directory.
        
        Returns:
            List of evidence bag directory names
        """
        if not self.output_dir.exists():
            return []
        
        bags = []
        for item in self.output_dir.iterdir():
            if item.is_dir():
                # Quick validation
                is_valid, _ = self.validate_bag_structure(str(item))
                if is_valid:
                    bags.append(item.name)
        
        return sorted(bags)
    
    def export_evidence(
        self,
        bag_path: str,
        output_path: str
    ) -> None:
        """
        Export original evidence file from bag.
        
        Args:
            bag_path: Path to evidence bag
            output_path: Destination path for evidence file
            
        Raises:
            FileNotFoundError: If bag or evidence not found
        """
        bag = Path(bag_path)
        evidence_source = bag / self.EVIDENCE_FILENAME
        
        if not evidence_source.exists():
            raise FileNotFoundError(
                f"Evidence file not found in bag: {evidence_source}"
            )
        
        shutil.copy2(evidence_source, output_path)
        print(f"[+] Evidence exported to: {output_path}")


# Example usage and testing
if __name__ == "__main__":
    import tempfile
    import json
    
    print("=== Forensic Evidence Packaging Module ===\n")
    
    # Initialize packager
    packager = EvidencePackager(output_dir="test_evidence_bags")
    
    # Create test evidence file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Top secret evidence for test case")
        test_evidence = f.name
    
    # Create test certificate
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.crt') as f:
        f.write("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----")
        test_cert = f.name
    
    try:
        print("[*] Creating test evidence bag...")
        
        # Test metadata
        metadata = {
            "case_id": "CASE-TEST-001",
            "investigator_id": "INV999",
            "seal_timestamp": datetime.now().isoformat(),
            "evidence": {
                "filename": "test_evidence.txt",
                "size_bytes": 1024,
                "description": "Test evidence"
            },
            "cryptography": {
                "hash_algorithm": "SHA256",
                "evidence_hash": "abc123",
                "signature_algorithm": "ECDSA-P256"
            }
        }
        
        # Test signature
        test_signature = b"TEST_SIGNATURE_BYTES"
        test_combined_hash = "def456"
        
        # Create bag
        bag_path = packager.create_evidence_bag(
            case_id="CASE-TEST-001",
            evidence_path=test_evidence,
            metadata=metadata,
            combined_hash=test_combined_hash,
            signature=test_signature,
            certificate_path=test_cert
        )
        
        # Validate bag structure
        print("\n[*] Validating bag structure...")
        is_valid, message = packager.validate_bag_structure(bag_path)
        print(f"[+] Validation: {is_valid} - {message}")
        
        # Display bag info
        packager.display_bag_info(bag_path)
        
        # List all bags
        print("[*] Listing all evidence bags...")
        bags = packager.list_evidence_bags()
        print(f"[+] Found {len(bags)} evidence bag(s): {bags}")
        
        # Cleanup test bag
        shutil.rmtree(bag_path)
        print("\n[*] Test bag cleaned up")
        
    finally:
        # Cleanup test files
        os.unlink(test_evidence)
        os.unlink(test_cert)
        print("[*] Test files cleaned up")