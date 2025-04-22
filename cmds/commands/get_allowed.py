#!/usr/bin/env python3
"""
This script gets all addresses from the list of authorized addresses
"""

import sys
import os

FILE = "/edge_node/_local_cache/authorized_addrs"

def main():
    # Check if the file exists
    if not os.path.isfile(FILE):
        print(f"Error: {FILE} does not exist", file=sys.stderr)
        sys.exit(1)
    
    # Read and print file content
    try:
        with open(FILE, "r") as f:
            print(f.read(), end="")
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 