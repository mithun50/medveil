#!/usr/bin/env python3
"""Entry point used by raksha.toml: python main.py --input {input} --output {output}"""
import sys

from medveil.cli import main

if __name__ == "__main__":
    sys.exit(main())
