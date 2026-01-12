#!/usr/bin/env python3
import sys
import os
from io import StringIO

# Check if env is loaded at module import time
print("[DEBUG] Before import app.py")
print(f"[DEBUG] OPENCAGE_API_KEY: {os.getenv('OPENCAGE_API_KEY', 'NOT SET')}")

# Simulate phone input
sys.stdin = StringIO('+237698021935\n')

# Now import CLI (which loads .env in app.py __init__)
from cli.modules.runner import ModuleRunner
from rich.console import Console

# Check again after import
print(f"[DEBUG] After import app.py")
print(f"[DEBUG] OPENCAGE_API_KEY: {os.getenv('OPENCAGE_API_KEY', 'NOT SET')}")

console = Console()
runner = ModuleRunner(console)

print("[DEBUG] Running phone_collector...")
runner.run_phone_collector()
