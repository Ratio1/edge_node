#!/usr/bin/env python3
"""
This script replaces the authorized addresses list with a batch of new addresses.
Each input line should be in format: <address> [alias]
Input is read from stdin, one address per line
Validates that there are no duplicate addresses or aliases

Example:
cat allowed_addresses.txt | docker exec -i <container> update_allowed_batch

allowed_addresses.txt:
<node-address1> <alias1>
<node-address2> <alias2>
...
"""

import sys
import os
import time
import subprocess
import tempfile

MAX_ALIAS_LENGTH = 15
FILE = "/edge_node/_local_cache/authorized_addrs"

def main():
    # Create a temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
        temp_file_path = temp_file.name
        
        # Dictionary to store used values for duplicate checking
        used_values = {}
        
        # Read input line by line and check for duplicates
        has_valid_entries = False
        
        for line in sys.stdin:
            # Skip empty lines
            line = line.strip()
            if not line:
                continue
                
            # Split line into address and alias
            parts = line.split(maxsplit=1)
            address = parts[0]
            alias = parts[1] if len(parts) > 1 else None
            
            # Truncate alias if it's longer than MAX_ALIAS_LENGTH
            if alias and len(alias) > MAX_ALIAS_LENGTH:
                print(f"Warning: Alias '{alias}' exceeds {MAX_ALIAS_LENGTH} characters, truncating to '{alias[:MAX_ALIAS_LENGTH]}'", 
                      file=sys.stderr)
                alias = alias[:MAX_ALIAS_LENGTH]
                
            # Check if address is already used (as either address or alias)
            if address in used_values:
                print(f"Error: Value '{address}' already used as {used_values[address]}", file=sys.stderr)
                os.unlink(temp_file_path)
                sys.exit(1)
                
            # Check if alias is already used (as either address or alias)
            if alias and alias in used_values:
                print(f"Error: Value '{alias}' already used as {used_values[alias]}", file=sys.stderr)
                os.unlink(temp_file_path)
                sys.exit(1)
                
            # Store both values with their roles for duplicate checking
            used_values[address] = "address"
            if alias:
                used_values[alias] = "alias"
                
            # Write valid line to temp file with potentially truncated alias
            if alias:
                temp_file.write(f"{address} {alias}\n")
            else:
                temp_file.write(f"{address}\n")
                
            has_valid_entries = True
    
    # Only replace the original file if we have at least one valid entry
    if has_valid_entries:
        os.rename(temp_file_path, FILE)
        time.sleep(3)
        subprocess.run(["get_node_info"])
    else:
        print("Error: No valid entries provided", file=sys.stderr)
        os.unlink(temp_file_path)
        sys.exit(1)

if __name__ == "__main__":
    main() 