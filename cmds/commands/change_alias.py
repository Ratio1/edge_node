#!/usr/bin/env python3
"""
change_alias:
  Usage: change_alias <new-alias>
  This script updates the "EE_ID" in /edge_node/_local_cache/config_startup.json.
  Example:
    docker exec <container> change_alias new-alias-name

Verbosity & Error Checks:
  - Verifies exactly one argument was passed.
  - Verifies /edge_node/_local_cache/config_startup.json exists and is valid JSON.
  - If "EE_ID" is missing, a warning is displayed, and the key is created.
  - Writes updated JSON using 2-space indentation.
  - Advises a node restart after modification.
"""

import sys
import json
import os

CONFIG_FILE = "/edge_node/_local_cache/config_startup.json"
MAX_ALIAS_LENGTH = 15

def main():
  # 1. Check argument count
  if len(sys.argv) != 2:
    print("Error: You must provide exactly one argument: <new-alias>")
    print("Usage: change_alias <new-alias>")
    sys.exit(1)

  new_alias = sys.argv[1].strip()

  # 2. Validate alias
  if not new_alias:
    print("Error: The new alias cannot be empty.")
    sys.exit(1)

  # 3. Check and truncate alias length
  if len(new_alias) > MAX_ALIAS_LENGTH:
    truncated_alias = new_alias[:MAX_ALIAS_LENGTH]
    print(f"Warning: Alias '{new_alias}' exceeds {MAX_ALIAS_LENGTH} characters, truncating to '{truncated_alias}'")
    new_alias = truncated_alias

  # 4. Check if the config file exists
  if not os.path.isfile(CONFIG_FILE):
    print(f"Error: {CONFIG_FILE} not found.")
    print("Cannot proceed with updating the alias.")
    sys.exit(1)

  # 5. Read and parse JSON
  try:
    with open(CONFIG_FILE, "r") as f:
      data = json.load(f)
  except json.JSONDecodeError as e:
    print(f"Error: Could not parse {CONFIG_FILE} as valid JSON.")
    print(f"Details: {e}")
    sys.exit(1)
  except OSError as e:
    print(f"Error: Failed to read {CONFIG_FILE}.")
    print(f"Details: {e}")
    sys.exit(1)

  # 6. Check for "EE_ID" key
  if "EE_ID" not in data:
    print(f"Warning: 'EE_ID' key not found in {CONFIG_FILE}. It will be created.")

  # 7. Update or set "EE_ID"
  old_alias = data.get("EE_ID")
  data["EE_ID"] = new_alias

  # 8. Write changes back to the JSON file
  try:
    with open(CONFIG_FILE, "w") as f:
      json.dump(data, f, indent=2)
      f.write("\n")  # Add a newline for cleanliness
  except OSError as e:
    print(f"Error: Failed to write updated data to {CONFIG_FILE}.")
    print(f"Details: {e}")
    sys.exit(1)

  # 9. Print success messages
  if old_alias is not None:
    print(f"Alias updated from '{old_alias}' to '{new_alias}' in {CONFIG_FILE}.")
  else:
    print(f"Alias set to '{new_alias}' in {CONFIG_FILE} (previously not defined).")

  print("A node restart is required for the change to take effect.")

if __name__ == "__main__":
  main() 