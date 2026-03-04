"""
Evidence Processing Module for Forensic PKI Tool

This module handles:
- Evidence file reading and validation
- Metadata generation with forensic fields
- Metadata canonicalization
- Evidence information extraction
"""

import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple
import hashlib


class EvidenceProcessor:
    """
    Processes digital evidence files and generates forensic metadata.
    
    Ensures evidence is properly documented with chain-of-custody
    information and cryptographic fingerprints.
    """
    
    def __init__(self):
        """Initialize the evidence processor."""
        self.metadata_version = "1.0"
    
    def validate_evidence_file(self, evidence_path: str) -> Tuple[bool, str]:
        """
        Validate that evidence file exists and is readable.
        
        Args:
            evidence_path: Path to evidence file
            
        Returns:
            Tuple of (is_valid, message)
        """
        evidence_file = Path(evidence_path)
        
        if not evidence_file.exists():
            return False, f"Evidence file does not exist: {evidence_path}"
        
        if not evidence_file.is_file():
            return False, f"Path is not a file: {evidence_path}"
        
        if not os.access(evidence_path, os.R_OK):
            return False, f"Evidence file is not readable: {evidence_path}"
        
        file_size = evidence_file.stat().st_size
        if file_size == 0:
            return False, "Evidence file is empty"
        
        return True, f"Evidence file valid ({file_size} bytes)"
    
    def get_file_info(self, file_path: str) -> Dict[str, any]:
        """
        Extract file system information from evidence file.
        
        Args:
            file_path: Path to evidence file
            
        Returns:
            Dictionary containing file information
        """
        file_stat = os.stat(file_path)
        file_path_obj = Path(file_path)
        
        return {
            "filename": file_path_obj.name,
            "original_path": str(file_path_obj.absolute()),
            "size_bytes": file_stat.st_size,
            "created_time": datetime.fromtimestamp(
                file_stat.st_ctime, tz=timezone.utc
            ).isoformat(),
            "modified_time": datetime.fromtimestamp(
                file_stat.st_mtime, tz=timezone.utc
            ).isoformat(),
            "accessed_time": datetime.fromtimestamp(
                file_stat.st_atime, tz=timezone.utc
            ).isoformat(),
        }
    
    def generate_metadata(
        self,
        case_id: str,
        investigator_id: str,
        evidence_path: str,
        evidence_hash: str,
        description: Optional[str] = None,
        additional_fields: Optional[Dict] = None
    ) -> Dict[str, any]:
        """
        Generate comprehensive forensic metadata for evidence.
        
        Metadata includes:
        - Case identification
        - Investigator identification
        - Temporal information
        - Evidence file information
        - Cryptographic hashes
        - Chain of custody information
        
        Args:
            case_id: Unique case identifier
            investigator_id: Investigator who sealed the evidence
            evidence_path: Path to evidence file
            evidence_hash: SHA-256 hash of evidence
            description: Optional evidence description
            additional_fields: Optional additional metadata fields
            
        Returns:
            Metadata dictionary
        """
        # Get file information
        file_info = self.get_file_info(evidence_path)
        
        # Generate timestamp in ISO 8601 format with UTC timezone
        seal_timestamp = datetime.now(timezone.utc).isoformat()
        
        # Build metadata structure
        metadata = {
            # Metadata version for future compatibility
            "metadata_version": self.metadata_version,
            
            # Case information
            "case_id": case_id,
            "case_title": additional_fields.get("case_title", "") if additional_fields else "",
            
            # Investigator information
            "investigator_id": investigator_id,
            "organization": additional_fields.get("organization", "") if additional_fields else "",
            
            # Temporal information
            "seal_timestamp": seal_timestamp,
            "timezone": "UTC",
            
            # Evidence file information
            "evidence": {
                "filename": file_info["filename"],
                "original_path": file_info["original_path"],
                "size_bytes": file_info["size_bytes"],
                "description": description or "",
                "file_created": file_info["created_time"],
                "file_modified": file_info["modified_time"],
                "file_accessed": file_info["accessed_time"],
            },
            
            # Cryptographic information
            "cryptography": {
                "hash_algorithm": "SHA256",
                "evidence_hash": evidence_hash,
                "signature_algorithm": "ECDSA-P256",
            },
            
            # Chain of custody
            "chain_of_custody": {
                "sealed_by": investigator_id,
                "seal_timestamp": seal_timestamp,
                "seal_location": additional_fields.get("location", "Unknown") if additional_fields else "Unknown",
                "custody_notes": additional_fields.get("notes", "") if additional_fields else "",
            }
        }
        
        return metadata
    
    def canonicalize_metadata(self, metadata: Dict) -> str:
        """
        Canonicalize metadata to JSON string for hashing.
        
        Ensures reproducible JSON representation with:
        - Sorted keys
        - Consistent spacing
        - UTF-8 encoding
        
        Args:
            metadata: Metadata dictionary
            
        Returns:
            Canonicalized JSON string
        """
        json_str = json.dumps(
            metadata,
            sort_keys=True,
            indent=2,  # Pretty print for readability
            separators=(',', ': '),
            ensure_ascii=True
        )
        
        return json_str
    
    def save_metadata(self, metadata: Dict, output_path: str) -> None:
        """
        Save metadata to JSON file.
        
        Args:
            metadata: Metadata dictionary
            output_path: Path to save metadata file
            
        Raises:
            IOError: If file cannot be written
        """
        try:
            json_str = self.canonicalize_metadata(metadata)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
                
        except Exception as e:
            raise IOError(f"Failed to save metadata: {e}")
    
    def load_metadata(self, metadata_path: str) -> Dict[str, any]:
        """
        Load metadata from JSON file.
        
        Args:
            metadata_path: Path to metadata file
            
        Returns:
            Metadata dictionary
            
        Raises:
            FileNotFoundError: If metadata file doesn't exist
            ValueError: If JSON is invalid
        """
        if not os.path.exists(metadata_path):
            raise FileNotFoundError(f"Metadata file not found: {metadata_path}")
        
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            
            return metadata
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in metadata file: {e}")
        except Exception as e:
            raise IOError(f"Failed to load metadata: {e}")
    
    def validate_metadata(self, metadata: Dict) -> Tuple[bool, str]:
        """
        Validate metadata structure and required fields.
        
        Args:
            metadata: Metadata dictionary to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        required_fields = [
            "metadata_version",
            "case_id",
            "investigator_id",
            "seal_timestamp",
            "evidence",
            "cryptography"
        ]
        
        for field in required_fields:
            if field not in metadata:
                return False, f"Missing required field: {field}"
        
        # Validate nested evidence fields
        evidence_fields = ["filename", "original_path", "size_bytes"]
        for field in evidence_fields:
            if field not in metadata["evidence"]:
                return False, f"Missing required evidence field: {field}"
        
        # Validate cryptographic fields
        crypto_fields = ["hash_algorithm", "evidence_hash", "signature_algorithm"]
        for field in crypto_fields:
            if field not in metadata["cryptography"]:
                return False, f"Missing required cryptography field: {field}"
        
        # Validate hash algorithm
        if metadata["cryptography"]["hash_algorithm"] != "SHA256":
            return False, "Invalid hash algorithm (must be SHA256)"
        
        # Validate signature algorithm
        if metadata["cryptography"]["signature_algorithm"] != "ECDSA-P256":
            return False, "Invalid signature algorithm (must be ECDSA-P256)"
        
        return True, "Metadata is valid"
    
    def display_metadata(self, metadata: Dict) -> None:
        """
        Display metadata in human-readable format.
        
        Args:
            metadata: Metadata dictionary to display
        """
        print("\n" + "="*60)
        print("FORENSIC EVIDENCE METADATA")
        print("="*60)
        
        print(f"\nCase Information:")
        print(f"  Case ID: {metadata.get('case_id', 'N/A')}")
        print(f"  Case Title: {metadata.get('case_title', 'N/A')}")
        
        print(f"\nInvestigator:")
        print(f"  ID: {metadata.get('investigator_id', 'N/A')}")
        print(f"  Organization: {metadata.get('organization', 'N/A')}")
        
        print(f"\nEvidence Seal:")
        print(f"  Timestamp: {metadata.get('seal_timestamp', 'N/A')}")
        
        if 'evidence' in metadata:
            evidence = metadata['evidence']
            print(f"\nEvidence File:")
            print(f"  Filename: {evidence.get('filename', 'N/A')}")
            print(f"  Size: {evidence.get('size_bytes', 0):,} bytes")
            print(f"  Description: {evidence.get('description', 'N/A')}")
        
        if 'cryptography' in metadata:
            crypto = metadata['cryptography']
            print(f"\nCryptographic Hash:")
            print(f"  Algorithm: {crypto.get('hash_algorithm', 'N/A')}")
            print(f"  Evidence Hash: {crypto.get('evidence_hash', 'N/A')}")
        
        if 'chain_of_custody' in metadata:
            custody = metadata['chain_of_custody']
            print(f"\nChain of Custody:")
            print(f"  Sealed By: {custody.get('sealed_by', 'N/A')}")
            print(f"  Location: {custody.get('seal_location', 'N/A')}")
            if custody.get('custody_notes'):
                print(f"  Notes: {custody.get('custody_notes')}")
        
        print("\n" + "="*60 + "\n")


# Example usage and testing
if __name__ == "__main__":
    import tempfile
    
    print("=== Forensic Evidence Processor Module ===\n")
    
    # Initialize processor
    processor = EvidenceProcessor()
    
    # Create test evidence file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Confidential case evidence: financial transaction records")
        test_file = f.name
    
    try:
        print(f"[*] Test evidence file: {test_file}")
        
        # Validate evidence file
        is_valid, message = processor.validate_evidence_file(test_file)
        print(f"[+] Validation: {is_valid} - {message}")
        
        # Get file info
        print("\n[*] Extracting file information...")
        file_info = processor.get_file_info(test_file)
        print(f"[+] File info: {json.dumps(file_info, indent=2)}")
        
        # Generate test hash
        from crypto_engine import CryptoEngine
        crypto = CryptoEngine()
        evidence_hash = crypto.hash_file(test_file)
        
        # Generate metadata
        print("\n[*] Generating metadata...")
        metadata = processor.generate_metadata(
            case_id="CASE-2025-001",
            investigator_id="INV001",
            evidence_path=test_file,
            evidence_hash=evidence_hash,
            description="Financial transaction evidence",
            additional_fields={
                "case_title": "Fraud Investigation",
                "organization": "Digital Forensics Lab",
                "location": "Lab 3, Building A",
                "notes": "Evidence collected from suspect's laptop"
            }
        )
        
        # Display metadata
        processor.display_metadata(metadata)
        
        # Validate metadata
        is_valid, message = processor.validate_metadata(metadata)
        print(f"[+] Metadata validation: {is_valid} - {message}")
        
        # Test metadata save/load
        print("\n[*] Testing metadata save/load...")
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            metadata_file = f.name
        
        processor.save_metadata(metadata, metadata_file)
        print(f"[+] Metadata saved to: {metadata_file}")
        
        loaded_metadata = processor.load_metadata(metadata_file)
        print(f"[+] Metadata loaded successfully")
        
        # Verify loaded metadata matches
        if metadata == loaded_metadata:
            print("[+] Loaded metadata matches original")
        else:
            print("[-] Metadata mismatch!")
        
        # Cleanup
        os.unlink(metadata_file)
        
    finally:
        # Cleanup test file
        os.unlink(test_file)
        print("\n[*] Test files cleaned up")