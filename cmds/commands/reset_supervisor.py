#!/usr/bin/env python3
"""
reset_supervisor:
  This script will create the file /shutdown_reset to reset the supervisor.
"""

def main():
    try:
        with open("/shutdown_reset", "w") as f:
            f.write("something\n")
        print("Supervisor reset requested.")
    except Exception as e:
        print(f"Error requesting supervisor reset: {e}")

if __name__ == "__main__":
    main() 