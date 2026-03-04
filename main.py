"""
Forensic PKI-Based Digital Evidence Integrity Tool

Main entry point for the command-line interface.
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.cli import main

if __name__ == "__main__":
    sys.exit(main())