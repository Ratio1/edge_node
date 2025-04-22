#!/usr/bin/env python3
"""
This script adds an address to the list of authorized addresses
Usage: add_allowed <address> [alias]

Example:
docker exec <container> add_allowed <node-address>
docker exec <container> add_allowed <node-address1> my-alias
"""

import sys
import os
import re
import time
import subprocess

MAX_ALIAS_LENGTH = 15
FILE = "/edge_node/_local_cache/authorized_addrs"

def main():
    # Check if at least one argument is provided
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <address> [alias]", file=sys.stderr)
        sys.exit(1)

    address = sys.argv[1]
    alias = sys.argv[2] if len(sys.argv) > 2 else None

    # Truncate alias if it's longer than MAX_ALIAS_LENGTH
    if alias and len(alias) > MAX_ALIAS_LENGTH:
        print(f"Warning: Alias '{alias}' exceeds {MAX_ALIAS_LENGTH} characters, truncating to '{alias[:MAX_ALIAS_LENGTH]}'", file=sys.stderr)
        alias = alias[:MAX_ALIAS_LENGTH]

    # Check if the file exists
    if not os.path.exists(FILE):
        print(f"Error: File {FILE} does not exist", file=sys.stderr)
        sys.exit(1)

    # Read existing content
    with open(FILE, "r") as f:
        lines = f.readlines()

    # Check if address already exists
    for line in lines:
        if line.startswith(address + " ") or line.strip() == address:
            print(f"Error: Address already exists: {address}", file=sys.stderr)
            sys.exit(1)

    # If alias is provided, check if it already exists
    if alias:
        for line in lines:
            if re.search(f" {re.escape(alias)}$", line):
                print(f"Error: Alias already exists: {alias}", file=sys.stderr)
                sys.exit(1)

    # Append the address and optional alias as a new line at the end of the file
    with open(FILE, "a") as f:
        if alias:
            f.write(f"{address}  {alias}\n")
        else:
            f.write(f"{address}\n")

    # Sleep before calling get_node_info
    time.sleep(3)
    
    # Call get_node_info
    subprocess.run(["get_node_info"])

if __name__ == "__main__":
    main() 