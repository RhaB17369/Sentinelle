#!/usr/bin/env python3
"""
SENTINNELLE Advanced CLI
Modularized Architecture - NSA/Unit 8200 Standard
"""

import os
import sys
import subprocess
from pathlib import Path

def ensure_venv():
    """Ensure the script runs within the project's virtual environment"""
    venv_path = Path(__file__).parent / "venv"
    if venv_path.exists() and not sys.prefix.startswith(str(venv_path)):
        python_exe = venv_path / "bin" / "python"
        if os.name == "nt":
            python_exe = venv_path / "Scripts" / "python.exe"
            
        if python_exe.exists():
            # Re-execute using the venv python
            os.execv(str(python_exe), [str(python_exe)] + sys.argv)

if __name__ == '__main__':
    ensure_venv()
    from cli.main import main
    main()
