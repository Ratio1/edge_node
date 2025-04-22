#!/usr/bin/env python3
"""
reset_node_keys:
  This script will reset the keys of the edge node - requires restart
"""

import os
import sys

def main():
    # Prompt for confirmation
    try:
        answer = input("Are you sure you want to reset the keys (private keys & node address)? [y/N]: ")
    except KeyboardInterrupt:
        print("\nOperation canceled.")
        sys.exit(0)
    
    # Compare the user's answer (case-insensitive) to 'y'
    if answer.lower() == 'y':
        # Proceed with removal
        file_path = "/edge_node/_local_cache/_data/e2.pem"
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            print("Keys have been reset. Please restart your node via 'docker restart r1node'")
        except Exception as e:
            print(f"Error removing keys: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Aborting key reset.")

if __name__ == "__main__":
    main() 