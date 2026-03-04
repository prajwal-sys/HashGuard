"""
Forensic PKI-Based Digital Evidence Integrity Tool

A production-grade system for sealing and verifying digital evidence
using Public Key Infrastructure (PKI) and cryptographic signatures.
"""

__version__ = "1.0.0"
__author__ = "Forensic Development Team"

from .key_management import InvestigatorKeyManager
from .crypto_engine import CryptoEngine
from .evidence_processor import EvidenceProcessor
from .packaging import EvidencePackager

__all__ = [
    "InvestigatorKeyManager",
    "CryptoEngine",
    "EvidenceProcessor",
    "EvidencePackager",
]