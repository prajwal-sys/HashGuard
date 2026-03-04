"""
Menu-Driven Interface Module for Forensic PKI Tool

Provides interactive menu system for:
- Creating investigators
- Sealing evidence
- Verifying evidence
- Managing investigators and evidence bags
"""

import sys
import os
import getpass
from pathlib import Path

from key_management import InvestigatorKeyManager
from crypto_engine import CryptoEngine
from evidence_processor import EvidenceProcessor
from packaging import EvidencePackager


class ForensicCLI:
    """
    Menu-driven interface for forensic evidence management.
    """
    
    def __init__(self):
        """Initialize CLI with all required modules."""
        self.key_manager = InvestigatorKeyManager()
        self.crypto_engine = CryptoEngine()
        self.evidence_processor = EvidenceProcessor()
        self.evidence_packager = EvidencePackager()
    
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self, title):
        """Print a formatted header."""
        print("\n" + "="*70)
        print(f"  {title}")
        print("="*70 + "\n")
    
    def print_box(self, message, char="*"):
        """Print a message in a box."""
        length = len(message) + 4
        print("\n" + char * length)
        print(f"{char} {message} {char}")
        print(char * length + "\n")
    
    def pause(self):
        """Pause and wait for user input."""
        input("\nPress ENTER to continue...")
    
    def get_input(self, prompt, default=None):
        """Get user input with optional default value."""
        if default:
            user_input = input(f"{prompt} [{default}]: ").strip()
            return user_input if user_input else default
        return input(f"{prompt}: ").strip()
    
    def get_password(self, prompt="Enter password"):
        """Get password input securely."""
        return getpass.getpass(f"{prompt}: ")
    
    def confirm(self, prompt):
        """Ask for yes/no confirmation."""
        while True:
            response = input(f"{prompt} (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no']:
                return False
            print("Please enter 'y' or 'n'")
    
    def select_from_list(self, items, prompt="Select an option"):
        """Display a numbered list and get user selection."""
        if not items:
            return None
        
        print(f"\n{prompt}:")
        for i, item in enumerate(items, 1):
            print(f"  {i}. {item}")
        
        while True:
            try:
                choice = input(f"\nEnter number (1-{len(items)}): ").strip()
                index = int(choice) - 1
                if 0 <= index < len(items):
                    return items[index]
                print(f"Please enter a number between 1 and {len(items)}")
            except ValueError:
                print("Please enter a valid number")
    
    def display_main_menu(self):
        """Display the main menu."""
        self.clear_screen()
        print("\n")
        print("╔" + "═"*68 + "╗")
        print("║" + " "*68 + "║")
        print("║" + "  PKI-BASED FORENSIC DIGITAL EVIDENCE INTEGRITY TOOL".center(68) + "║")
        print("║" + "  Cryptographic Evidence Sealing & Verification System".center(68) + "║")
        print("║" + " "*68 + "║")
        print("╚" + "═"*68 + "╝")
        print("\n" + "─"*70)
        print("  MAIN MENU")
        print("─"*70)
        print("\n  1. 🔑 Investigator Management")
        print("  2. 📦 Seal Evidence")
        print("  3. ✓  Verify Evidence")
        print("  4. 📋 View Evidence Bags")
        print("  5. ℹ️  About This Tool")
        print("  6. 🚪 Exit")
        print("\n" + "─"*70)
    
    def display_investigator_menu(self):
        """Display investigator management menu."""
        self.clear_screen()
        self.print_header("INVESTIGATOR MANAGEMENT")
        print("  1. Create New Investigator")
        print("  2. List All Investigators")
        print("  3. View Investigator Details")
        print("  4. Back to Main Menu")
        print("\n" + "─"*70)
    
    def create_investigator(self):
        """Create a new investigator interactively."""
        self.clear_screen()
        self.print_header("CREATE NEW INVESTIGATOR")
        
        print("This will create cryptographic credentials for a forensic investigator.")
        print("You will need to provide:")
        print("  • Investigator ID (unique identifier)")
        print("  • Password (to protect private key)")
        print("  • Organization details")
        print()
        
        # Get investigator details
        investigator_id = self.get_input("Investigator ID (e.g., INV001)")
        if not investigator_id:
            print("\n❌ Investigator ID is required")
            self.pause()
            return
        
        organization = self.get_input("Organization name", "Digital Forensics Lab")
        country = self.get_input("Country code (2 letters)", "US")
        
        # Validate country code
        if len(country) != 2:
            print("\n❌ Country code must be exactly 2 letters")
            self.pause()
            return
        
        validity_days = self.get_input("Certificate validity (days)", "365")
        try:
            validity_days = int(validity_days)
        except ValueError:
            print("\n❌ Validity days must be a number")
            self.pause()
            return
        
        # Get password
        print("\n" + "─"*70)
        print("Password Requirements:")
        print("  • Minimum 8 characters")
        print("  • Keep it secure - there is NO password recovery!")
        print("─"*70)
        
        password = self.get_password("Enter password for private key")
        password_confirm = self.get_password("Confirm password")
        
        if password != password_confirm:
            print("\n❌ Passwords do not match")
            self.pause()
            return
        
        if len(password) < 8:
            print("\n❌ Password must be at least 8 characters")
            self.pause()
            return
        
        # Confirm creation
        print("\n" + "─"*70)
        print("Ready to create investigator:")
        print(f"  ID: {investigator_id}")
        print(f"  Organization: {organization}")
        print(f"  Country: {country}")
        print(f"  Validity: {validity_days} days")
        print("─"*70)
        
        if not self.confirm("\nProceed with creation?"):
            print("\n❌ Creation cancelled")
            self.pause()
            return
        
        try:
            print("\n⏳ Generating cryptographic credentials...")
            private_key_path, certificate_path = self.key_manager.generate_investigator_keypair(
                investigator_id=investigator_id,
                password=password,
                organization=organization,
                country=country,
                validity_days=validity_days
            )
            
            self.print_box("✓ INVESTIGATOR CREATED SUCCESSFULLY", "=")
            print(f"Investigator ID: {investigator_id}")
            print(f"Private Key: {private_key_path}")
            print(f"Certificate: {certificate_path}")
            print("\n⚠️  Keep your password secure - it cannot be recovered!")
            
        except ValueError as e:
            print(f"\n❌ Error: {e}")
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
        
        self.pause()
    
    def list_investigators_interactive(self):
        """List all investigators interactively."""
        self.clear_screen()
        self.print_header("REGISTERED INVESTIGATORS")
        
        investigators = self.key_manager.list_investigators()
        
        if not investigators:
            print("No investigators found.")
            print("\nCreate an investigator from the Investigator Management menu.")
        else:
            print(f"Found {len(investigators)} investigator(s):\n")
            print(f"{'ID':<20} {'Status':<30} {'Expires'}")
            print("─"*70)
            
            for inv_id in investigators:
                try:
                    cert = self.key_manager.load_certificate(inv_id)
                    is_valid, message = self.key_manager.validate_certificate(cert)
                    
                    status = "✓ Valid" if is_valid else f"✗ {message}"
                    expires = cert.not_valid_after.strftime("%Y-%m-%d")
                    
                    print(f"{inv_id:<20} {status:<30} {expires}")
                except Exception as e:
                    print(f"{inv_id:<20} {'✗ Error loading certificate':<30}")
        
        print("\n" + "─"*70)
        self.pause()
    
    def view_investigator_details(self):
        """View detailed information about an investigator."""
        self.clear_screen()
        self.print_header("INVESTIGATOR DETAILS")
        
        investigators = self.key_manager.list_investigators()
        
        if not investigators:
            print("No investigators found.")
            self.pause()
            return
        
        investigator_id = self.select_from_list(investigators, "Select investigator")
        if not investigator_id:
            return
        
        try:
            cert = self.key_manager.load_certificate(investigator_id)
            is_valid, message = self.key_manager.validate_certificate(cert)
            
            print("\n" + "─"*70)
            print(f"Investigator ID: {investigator_id}")
            print(f"Subject: {cert.subject.rfc4514_string()}")
            print(f"Serial Number: {cert.serial_number}")
            print(f"Valid From: {cert.not_valid_before}")
            print(f"Valid Until: {cert.not_valid_after}")
            print(f"Status: {message}")
            print(f"Certificate Path: {self.key_manager.data_dir / investigator_id / 'certificate.crt'}")
            print("─"*70)
            
        except Exception as e:
            print(f"\n❌ Error loading investigator: {e}")
        
        self.pause()
    
    def investigator_management_menu(self):
        """Handle investigator management submenu."""
        while True:
            self.display_investigator_menu()
            choice = self.get_input("\nSelect option (1-4)")
            
            if choice == '1':
                self.create_investigator()
            elif choice == '2':
                self.list_investigators_interactive()
            elif choice == '3':
                self.view_investigator_details()
            elif choice == '4':
                break
            else:
                print("\n❌ Invalid choice. Please select 1-4")
                self.pause()
    
    def seal_evidence_interactive(self):
        """Seal evidence file interactively."""
        self.clear_screen()
        self.print_header("SEAL FORENSIC EVIDENCE")
        
        # Check if investigators exist
        investigators = self.key_manager.list_investigators()
        if not investigators:
            print("❌ No investigators found!")
            print("\nYou must create an investigator first.")
            print("Go to: Main Menu → Investigator Management → Create New Investigator")
            self.pause()
            return
        
        # Select investigator
        print("Step 1: Select Investigator")
        print("─"*70)
        investigator_id = self.select_from_list(investigators, "Choose investigator")
        if not investigator_id:
            return
        
        # Get evidence file
        print("\n" + "─"*70)
        print("Step 2: Specify Evidence File")
        print("─"*70)
        evidence_path = self.get_input("Enter path to evidence file")
        
        if not evidence_path:
            print("\n❌ Evidence file path is required")
            self.pause()
            return
        
        # Validate evidence file
        is_valid, message = self.evidence_processor.validate_evidence_file(evidence_path)
        if not is_valid:
            print(f"\n❌ {message}")
            self.pause()
            return
        
        print(f"✓ {message}")
        
        # Get case information
        print("\n" + "─"*70)
        print("Step 3: Case Information")
        print("─"*70)
        case_id = self.get_input("Case ID (e.g., CASE-2025-001)")
        if not case_id:
            print("\n❌ Case ID is required")
            self.pause()
            return
        
        case_title = self.get_input("Case title (optional)", "")
        description = self.get_input("Evidence description (optional)", "")
        
        # Get chain of custody information
        print("\n" + "─"*70)
        print("Step 4: Chain of Custody (Optional)")
        print("─"*70)
        organization = self.get_input("Organization name", "")
        location = self.get_input("Seal location", "")
        notes = self.get_input("Custody notes", "")
        
        # Get password
        print("\n" + "─"*70)
        print("Step 5: Authentication")
        print("─"*70)
        password = self.get_password(f"Enter password for investigator {investigator_id}")
        
        # Summary
        print("\n" + "="*70)
        print("EVIDENCE SEALING SUMMARY")
        print("="*70)
        print(f"Evidence File: {evidence_path}")
        print(f"Case ID: {case_id}")
        print(f"Investigator: {investigator_id}")
        if case_title:
            print(f"Case Title: {case_title}")
        if description:
            print(f"Description: {description}")
        print("="*70)
        
        if not self.confirm("\nProceed with sealing?"):
            print("\n❌ Sealing cancelled")
            self.pause()
            return
        
        try:
            # Load investigator credentials
            print("\n⏳ Loading investigator credentials...")
            private_key = self.key_manager.load_private_key(investigator_id, password)
            certificate = self.key_manager.load_certificate(investigator_id)
            
            # Validate certificate
            is_valid, cert_message = self.key_manager.validate_certificate(certificate)
            if not is_valid:
                print(f"\n❌ Certificate validation failed: {cert_message}")
                self.pause()
                return
            
            print("✓ Credentials loaded and validated")
            
            # Hash evidence file
            print("\n⏳ Computing cryptographic hashes...")
            evidence_hash = self.crypto_engine.hash_file(evidence_path)
            print(f"✓ Evidence SHA-256: {evidence_hash[:32]}...")
            
            # Generate metadata
            additional_fields = {
                "case_title": case_title or "",
                "organization": organization or "",
                "location": location or "",
                "notes": notes or ""
            }
            
            metadata = self.evidence_processor.generate_metadata(
                case_id=case_id,
                investigator_id=investigator_id,
                evidence_path=evidence_path,
                evidence_hash=evidence_hash,
                description=description,
                additional_fields=additional_fields
            )
            
            metadata_hash = self.crypto_engine.hash_metadata(metadata)
            print(f"✓ Metadata SHA-256: {metadata_hash[:32]}...")
            
            # Create evidence seal
            print("\n⏳ Creating digital signature...")
            combined_hash, signature = self.crypto_engine.create_evidence_seal(
                evidence_hash=evidence_hash,
                metadata_hash=metadata_hash,
                private_key=private_key
            )
            print(f"✓ Combined hash: {combined_hash[:32]}...")
            print(f"✓ Digital signature: {len(signature)} bytes")
            
            # Get certificate path
            certificate_path = self.key_manager.data_dir / investigator_id / "certificate.crt"
            
            # Create evidence bag
            print("\n⏳ Creating evidence bag...")
            bag_path = self.evidence_packager.create_evidence_bag(
                case_id=case_id,
                evidence_path=evidence_path,
                metadata=metadata,
                combined_hash=combined_hash,
                signature=signature,
                certificate_path=str(certificate_path)
            )
            
            self.print_box("✓ EVIDENCE SEALED SUCCESSFULLY", "=")
            print(f"Evidence bag location:")
            print(f"  {bag_path}")
            print("\nThe evidence bag contains:")
            print("  ✓ Original evidence file")
            print("  ✓ Forensic metadata (JSON)")
            print("  ✓ Cryptographic hashes")
            print("  ✓ Digital signature")
            print("  ✓ Investigator certificate")
            print("\nThis evidence is now cryptographically sealed and tamper-evident.")
            
        except FileNotFoundError as e:
            print(f"\n❌ {e}")
        except ValueError as e:
            print(f"\n❌ {e}")
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
        
        self.pause()
    
    def verify_evidence_interactive(self):
        """Verify evidence bag interactively."""
        self.clear_screen()
        self.print_header("VERIFY FORENSIC EVIDENCE")
        
        # Check if evidence bags exist
        bags = self.evidence_packager.list_evidence_bags()
        
        if not bags:
            print("No evidence bags found.")
            print("\nSeal evidence first from: Main Menu → Seal Evidence")
            print("\nOr enter a custom path:")
            bag_path = self.get_input("Evidence bag path (or press ENTER to cancel)", "")
            if not bag_path:
                self.pause()
                return
        else:
            print(f"Found {len(bags)} evidence bag(s)")
            print("\nOptions:")
            print("  1. Select from list")
            print("  2. Enter custom path")
            
            choice = self.get_input("\nSelect option (1-2)")
            
            if choice == '1':
                bag_name = self.select_from_list(bags, "Select evidence bag to verify")
                if not bag_name:
                    return
                bag_path = str(self.evidence_packager.output_dir / bag_name)
            elif choice == '2':
                bag_path = self.get_input("Enter evidence bag path")
            else:
                print("\n❌ Invalid choice")
                self.pause()
                return
        
        if not bag_path:
            print("\n❌ No evidence bag selected")
            self.pause()
            return
        
        print("\n" + "="*70)
        print("STARTING VERIFICATION")
        print("="*70)
        
        try:
            # Validate bag structure
            print("\n⏳ Validating evidence bag structure...")
            is_valid, message = self.evidence_packager.validate_bag_structure(bag_path)
            if not is_valid:
                print(f"❌ {message}")
                self.pause()
                return
            print(f"✓ {message}")
            
            # Load evidence bag
            print("\n⏳ Loading evidence bag components...")
            bag_data = self.evidence_packager.load_evidence_bag(bag_path)
            
            metadata = bag_data['metadata']
            evidence_file_path = bag_data['evidence_file_path']
            combined_hash = bag_data['combined_hash']
            signature = bag_data['signature']
            certificate = bag_data['certificate']
            
            print("✓ Evidence bag loaded")
            
            # Display metadata
            self.evidence_processor.display_metadata(metadata)
            
            # Validate metadata
            print("⏳ Validating metadata structure...")
            is_valid, message = self.evidence_processor.validate_metadata(metadata)
            if not is_valid:
                print(f"❌ Metadata validation failed: {message}")
                self.pause()
                return
            print(f"✓ {message}")
            
            # Validate certificate
            print("\n⏳ Validating investigator certificate...")
            skip_expiry = False
            is_valid, cert_message = self.key_manager.validate_certificate(
                certificate,
                check_expiry=True
            )
            
            if not is_valid and "expired" in cert_message.lower():
                print(f"⚠️  {cert_message}")
                if self.confirm("Certificate is expired. Continue verification anyway?"):
                    skip_expiry = True
                    is_valid = True
                else:
                    self.pause()
                    return
            elif not is_valid:
                print(f"❌ Certificate validation failed: {cert_message}")
                self.pause()
                return
            else:
                print(f"✓ {cert_message}")
            
            # Extract investigator ID from certificate
            cert_inv_id = self.key_manager.get_investigator_id_from_certificate(certificate)
            metadata_inv_id = metadata.get('investigator_id')
            
            if cert_inv_id != metadata_inv_id:
                print(f"\n❌ Investigator ID mismatch!")
                print(f"    Certificate: {cert_inv_id}")
                print(f"    Metadata: {metadata_inv_id}")
                self.pause()
                return
            
            # Recompute evidence hash
            print("\n⏳ Recomputing evidence hash...")
            computed_evidence_hash = self.crypto_engine.hash_file(evidence_file_path)
            expected_evidence_hash = metadata['cryptography']['evidence_hash']
            
            if computed_evidence_hash != expected_evidence_hash:
                print("\n" + "!"*70)
                print("❌ EVIDENCE HASH MISMATCH - EVIDENCE HAS BEEN ALTERED!")
                print("!"*70)
                print(f"\nExpected: {expected_evidence_hash}")
                print(f"Computed: {computed_evidence_hash}")
                print("\n⚠️  WARNING: This evidence has been tampered with!")
                print("⚠️  DO NOT use this evidence in legal proceedings!")
                print("!"*70)
                self.pause()
                return
            
            print(f"✓ Evidence hash verified: {computed_evidence_hash[:32]}...")
            
            # Recompute metadata hash
            print("\n⏳ Recomputing metadata hash...")
            computed_metadata_hash = self.crypto_engine.hash_metadata(metadata)
            print(f"✓ Metadata hash computed: {computed_metadata_hash[:32]}...")
            
            # Verify complete seal
            print("\n⏳ Verifying digital signature...")
            is_valid, seal_message = self.crypto_engine.verify_evidence_seal(
                evidence_hash=computed_evidence_hash,
                metadata_hash=computed_metadata_hash,
                expected_combined_hash=combined_hash,
                signature=signature,
                certificate=certificate
            )
            
            print("\n" + "="*70)
            if is_valid:
                print("✓✓✓ VERIFICATION SUCCESSFUL ✓✓✓")
                print("="*70)
                print("\n✓ Evidence integrity: INTACT")
                print("✓ Digital signature: VALID")
                print("✓ Authenticity: VERIFIED")
                print("\nThis evidence has NOT been altered since sealing.")
                print(f"\nSealed by: {metadata_inv_id}")
                print(f"Seal timestamp: {metadata.get('seal_timestamp')}")
                print(f"Case ID: {metadata.get('case_id')}")
                
                if skip_expiry:
                    print("\n⚠️  Note: Certificate is expired (verification allowed by user)")
            else:
                print("❌❌❌ VERIFICATION FAILED ❌❌❌")
                print("="*70)
                print(f"\n❌ {seal_message}")
                print("\n⚠️  WARNING: Evidence integrity or authenticity cannot be verified!")
                print("⚠️  DO NOT use this evidence in legal proceedings!")
            
            print("="*70)
            
        except Exception as e:
            print(f"\n❌ Verification error: {e}")
            import traceback
            traceback.print_exc()
        
        self.pause()
    
    def view_evidence_bags(self):
        """View all evidence bags with details."""
        self.clear_screen()
        self.print_header("EVIDENCE BAGS")
        
        bags = self.evidence_packager.list_evidence_bags()
        
        if not bags:
            print("No evidence bags found.")
            print("\nSeal evidence first from: Main Menu → Seal Evidence")
            self.pause()
            return
        
        print(f"Found {len(bags)} evidence bag(s):\n")
        
        for i, bag_name in enumerate(bags, 1):
            print(f"{i}. {bag_name}")
        
        print("\n" + "─"*70)
        print("\nOptions:")
        print("  1. View detailed information about a bag")
        print("  2. Return to main menu")
        
        choice = self.get_input("\nSelect option (1-2)")
        
        if choice == '1':
            bag_name = self.select_from_list(bags, "Select evidence bag")
            if bag_name:
                bag_path = str(self.evidence_packager.output_dir / bag_name)
                self.show_bag_details(bag_path)
        
    def show_bag_details(self, bag_path):
        """Show detailed information about an evidence bag."""
        self.clear_screen()
        self.print_header("EVIDENCE BAG DETAILS")
        
        try:
            bag_data = self.evidence_packager.load_evidence_bag(bag_path)
            metadata = bag_data['metadata']
            
            print(f"Bag Location: {bag_path}\n")
            print("─"*70)
            
            # Case information
            print("\n📋 CASE INFORMATION")
            print(f"  Case ID: {metadata.get('case_id', 'N/A')}")
            print(f"  Case Title: {metadata.get('case_title', 'N/A')}")
            
            # Investigator information
            print("\n👤 INVESTIGATOR")
            print(f"  ID: {metadata.get('investigator_id', 'N/A')}")
            print(f"  Organization: {metadata.get('organization', 'N/A')}")
            
            # Evidence information
            if 'evidence' in metadata:
                evidence = metadata['evidence']
                print("\n📦 EVIDENCE FILE")
                print(f"  Filename: {evidence.get('filename', 'N/A')}")
                print(f"  Size: {evidence.get('size_bytes', 0):,} bytes")
                print(f"  Description: {evidence.get('description', 'N/A')}")
            
            # Seal information
            print("\n🔒 SEAL INFORMATION")
            print(f"  Timestamp: {metadata.get('seal_timestamp', 'N/A')}")
            
            # Cryptographic information
            if 'cryptography' in metadata:
                crypto = metadata['cryptography']
                print("\n🔐 CRYPTOGRAPHY")
                print(f"  Hash Algorithm: {crypto.get('hash_algorithm', 'N/A')}")
                print(f"  Signature Algorithm: {crypto.get('signature_algorithm', 'N/A')}")
                print(f"  Evidence Hash: {crypto.get('evidence_hash', 'N/A')[:64]}...")
            
            # Chain of custody
            if 'chain_of_custody' in metadata:
                custody = metadata['chain_of_custody']
                print("\n📜 CHAIN OF CUSTODY")
                print(f"  Sealed By: {custody.get('sealed_by', 'N/A')}")
                print(f"  Location: {custody.get('seal_location', 'N/A')}")
                if custody.get('custody_notes'):
                    print(f"  Notes: {custody.get('custody_notes')}")
            
            print("\n" + "─"*70)
            
        except Exception as e:
            print(f"\n❌ Error loading bag details: {e}")
        
        self.pause()
    
    def show_about(self):
        """Display information about the tool."""
        self.clear_screen()
        print("\n")
        print("╔" + "═"*68 + "╗")
        print("║" + " "*68 + "║")
        print("║" + "  PKI-BASED FORENSIC EVIDENCE INTEGRITY TOOL".center(68) + "║")
        print("║" + " "*68 + "║")
        print("╚" + "═"*68 + "╝")
        print("\n" + "─"*70)
        print("  ABOUT THIS TOOL")
        print("─"*70)
        
        print("\nThis is a forensic-grade digital evidence management system that")
        print("ensures authenticity, integrity, and chain-of-custody verification")
        print("using Public Key Infrastructure (PKI).")
        
        print("\n📌 KEY FEATURES:")
        print("  • ECC P-256 (SECP256R1) asymmetric cryptography")
        print("  • ECDSA digital signatures for non-repudiation")
        print("  • SHA-256 cryptographic hashing")
        print("  • X.509 certificates for identity binding")
        print("  • Tamper-evident evidence packaging")
        print("  • Complete chain of custody tracking")
        
        print("\n🔒 SECURITY:")
        print("  • NIST-approved algorithms")
        print("  • Password-encrypted private keys")
        print("  • Cryptographic proof of integrity")
        print("  • Digital signature authentication")
        
        print("\n📚 USE CASES:")
        print("  • Law enforcement evidence management")
        print("  • Corporate fraud investigations")
        print("  • Digital forensics education")
        print("  • Legal admissibility requirements")
        
        print("\n⚖️  COMPLIANCE:")
        print("  • NIST FIPS 186-4 (Digital Signatures)")
        print("  • NIST FIPS 180-4 (SHA-256)")
        print("  • RFC 5280 (X.509 Certificates)")
        print("  • ISO/IEC 27037 (Digital Evidence)")
        
        print("\n📝 VERSION: 1.0.0")
        print("📅 DATE: February 2025")
        
        print("\n" + "─"*70)
        self.pause()
    
    def run(self):
        """Main menu loop."""
        while True:
            self.display_main_menu()
            choice = self.get_input("\nSelect option (1-6)")
            
            if choice == '1':
                self.investigator_management_menu()
            elif choice == '2':
                self.seal_evidence_interactive()
            elif choice == '3':
                self.verify_evidence_interactive()
            elif choice == '4':
                self.view_evidence_bags()
            elif choice == '5':
                self.show_about()
            elif choice == '6':
                self.clear_screen()
                print("\n" + "="*70)
                print("  Thank you for using the Forensic PKI Tool")
                print("  Stay secure! 🔒")
                print("="*70 + "\n")
                sys.exit(0)
            else:
                print("\n❌ Invalid choice. Please select 1-6")
                self.pause()


def main():
    """Main entry point for menu-driven interface."""
    cli = ForensicCLI()
    
    try:
        cli.run()
    except KeyboardInterrupt:
        cli.clear_screen()
        print("\n\n⚠️  Operation cancelled by user")
        print("Exiting safely...\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    sys.exit(main())