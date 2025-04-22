#!/usr/bin/env python3
"""
This script displays the contents of the e2.pem file used for edge node authentication
If the file doesn't exist, it will display an appropriate message
"""

import os

FILE = "/edge_node/_local_cache/_data/e2.pem"

def main():
    # Check if the file exists
    if os.path.isfile(FILE):
        try:
            with open(FILE, "r") as f:
                print(f.read())
            print(f"\nSuccessfully displayed {FILE}")
        except Exception as e:
            print(f"Error reading file: {e}")
    else:
        print(f"File {FILE} does not exist")

if __name__ == "__main__":
    main() 