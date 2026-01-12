#!/usr/bin/env python3
"""Simple test of Phone Intelligence with GPS"""

import sys
from io import StringIO
import os

# Set up stdin
sys.stdin = StringIO('+237698021935\n')

# Import CLI
from cli.modules.runner import ModuleRunner
from rich.console import Console

# Check API key
api_key = os.getenv('OPENCAGE_API_KEY')
print(f"✓ OPENCAGE_API_KEY loaded: {bool(api_key)}")
if api_key:
    print(f"✓ Key (first 10 chars): {api_key[:10]}...\n")

# Run
console = Console()
runner = ModuleRunner(console)
runner.run_phone_collector()
