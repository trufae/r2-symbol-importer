#!/usr/bin/env python3
"""
CLI entry point when invoked as `python3 -m r2_symbol_importer`.
"""

import sys
from r2_symbol_importer.r2_plugin import main

if __name__ == "__main__":
    sys.exit(main())
