#!/usr/bin/env python3
"""Test Email OSINT integration with engine_mail_collector"""

import sys
from io import StringIO

# Simulate user input for email
sys.stdin = StringIO('test@example.com\n')

from cli.modules.runner import ModuleRunner
from rich.console import Console

console = Console()
runner = ModuleRunner(console)

print("Testing Email OSINT Module Integration...")
print("=" * 60)
print(f"EMAIL_OSINT_AVAILABLE: {runner.__class__.__module__}")

# Check if email_core is available
try:
    from engine_mail_collector.core import is_email
    print("✓ engine_mail_collector.core imported successfully")
    print(f"✓ is_email('test@example.com'): {is_email('test@example.com')}")
    print(f"✓ is_email('invalid'): {is_email('invalid')}")
except ImportError as e:
    print(f"✗ Failed to import engine_mail_collector: {e}")

print("\n" + "=" * 60)
print("Running Email OSINT...")
print("=" * 60 + "\n")

try:
    runner.run_email_osint()
except EOFError:
    print("\n[Completed - EOF reached]")
except Exception as e:
    print(f"\n[Error: {e}]")
