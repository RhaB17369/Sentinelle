#!/usr/bin/env python3
import os
import sys

# Ensure src/ is in the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from sentinelle.interface.app import main

if __name__ == '__main__':
    main()
