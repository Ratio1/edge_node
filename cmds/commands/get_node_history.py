#!/usr/bin/env python3
"""
This script will dump the local history JSON of the edge node
"""

import sys
import os
import json

FILE = "/edge_node/_local_cache/_data/local_history.json"

def main():
    # Check if the file exists
    if not os.path.isfile(FILE):
        print(f"Error: {FILE} does not exist", file=sys.stderr)
        sys.exit(1)
    
    # Read and print the file content with a newline at the end
    try:
        with open(FILE, "r") as f:
            print(f.read())
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 