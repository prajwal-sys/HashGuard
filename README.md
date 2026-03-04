# Forensic PKI Evidence Integrity Tool

A cryptographic evidence management system that ensures the authenticity and integrity of digital evidence using Public Key Infrastructure (PKI) and digital signatures.

## 🎯 What It Does

- **Seal Evidence**: Cryptographically protect digital evidence with tamper-evident seals
- **Verify Evidence**: Prove evidence has not been altered since sealing
- **Chain of Custody**: Maintain complete forensic documentation
- **Non-Repudiation**: Digital signatures prove who sealed the evidence

## 🔒 Security Features

- **ECC P-256** asymmetric cryptography (NIST-approved)
- **ECDSA** digital signatures for authentication
- **SHA-256** cryptographic hashing for integrity
- **X.509 certificates** for investigator identity
- **Password-encrypted** private keys

## 🚀 Quick Start

```bash
# Install dependencies
pip install cryptography

# Run the interactive menu
python main.py
```

### First-Time Setup

1. **Create an investigator** (one-time):
   - Select: Main Menu → 1 → 1
   - Enter ID, password, and organization details

2. **Seal evidence**:
   - Select: Main Menu → 2
   - Choose investigator, evidence file, and case details

3. **Verify evidence**:
   - Select: Main Menu → 3
   - Select evidence bag to verify

## 📦 What Gets Created

When you seal evidence, the tool creates an evidence bag containing:

```
evidence_bags/CASE-2025-001_photo_20260208_120000/
├── evidence_file          # Original evidence (preserved)
├── metadata.json          # Case info, timestamps, chain of custody
├── combined.hash          # SHA-256 cryptographic hash
├── signature.sig          # ECDSA digital signature
├── investigator.crt       # Investigator's X.509 certificate
└── MANIFEST.txt           # Contents inventory
```

## ✅ Verification Results

**Evidence Intact:**
```
✓✓✓ VERIFICATION SUCCESSFUL ✓✓✓

✓ Evidence integrity: INTACT
✓ Digital signature: VALID
✓ Authenticity: VERIFIED
```

**Evidence Tampered:**
```
❌ EVIDENCE HASH MISMATCH - EVIDENCE HAS BEEN ALTERED!
⚠️  WARNING: This evidence has been tampered with!
```

## 🎓 Academic Project

This tool was developed as a final-year cryptography project demonstrating:
- Public Key Infrastructure (PKI) implementation
- Digital signature schemes (ECDSA)
- Forensic chain of custody management
- Secure evidence handling workflows

## 🛠️ Technical Stack

- **Python 3.8+**
- **cryptography library** (for ECC, ECDSA, X.509)
- **Standard library** (hashlib, json, pathlib)

## ⚖️ Standards Compliance

- NIST FIPS 186-4 (Digital Signatures)
- NIST FIPS 180-4 (SHA-256)
- RFC 5280 (X.509 Certificates)
- ISO/IEC 27037 (Digital Evidence)

## 🔐 Use Cases

- Law enforcement evidence management
- Corporate fraud investigations
- Digital forensics training
- Legal admissibility requirements
- Chain of custody documentation

## ⚠️ Important Notes

- **Password Security**: Keep investigator passwords secure - they cannot be recovered
- **Evidence Storage**: Store evidence bags in secure, backed-up locations
- **Legal Use**: Consult legal experts for admissibility requirements in your jurisdiction
- **No Encryption**: Evidence files are stored in plaintext (integrity, not confidentiality)

## 📞 Quick Reference

| Task | Menu Path |
|------|-----------|
| Create investigator | Main → 1 → 1 |
| Seal evidence | Main → 2 |
| Verify evidence | Main → 3 |
| View evidence bags | Main → 4 |

---

**Version**: 2.0 (Menu-Driven Interface)  
**License**: Academic/Educational Use  
**Date**: February 2026