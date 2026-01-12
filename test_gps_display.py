#!/usr/bin/env python3
"""Test script to verify GPS coordinates display in CLI"""

import sys
import os
from pathlib import Path
from io import StringIO

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

# Load .env explicitly
from dotenv import load_dotenv
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    load_dotenv(env_path)

print("=" * 60)
print("Testing GPS Coordinates Display in Phone Intelligence")
print("=" * 60)

# Verify API key is loaded
api_key = os.getenv('OPENCAGE_API_KEY')
print(f"\n✓ OPENCAGE_API_KEY loaded: {bool(api_key)}")
if api_key:
    print(f"✓ Key (first 10 chars): {api_key[:10]}...")
else:
    print("✗ Key is None - GPS will not display!")

print("\n" + "=" * 60)
print("Running Phone Intelligence Module with test number")
print("=" * 60)

# Simulate user input
user_input = '+237698021935\n'
sys.stdin = StringIO(user_input)

# Import and run
from cli.modules.runner import ModuleRunner
from rich.console import Console

console = Console()
runner = ModuleRunner(console)

# Run phone collector
runner.run_phone_collector()
