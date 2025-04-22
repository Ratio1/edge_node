#!/usr/bin/env python3
"""
This script sets up the environment for compiling the Python command scripts into binaries.
It installs PyInstaller and any other dependencies needed.

Usage:
python setup_compilation.py
"""

import os
import sys
import subprocess
import shutil

def main():
    print("Setting up environment for compiling Python scripts to binaries...")
    
    # Check if pip is available
    if shutil.which("pip") is None:
        print("Error: pip is not installed. Please install pip first.", file=sys.stderr)
        sys.exit(1)
    
    # Install PyInstaller
    print("Installing PyInstaller...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error installing PyInstaller: {e}", file=sys.stderr)
        sys.exit(1)
    
    print("PyInstaller installed successfully.")
    
    # Create a compilation script
    compile_script = """#!/usr/bin/env python3
import os
import sys
import subprocess
import glob

def compile_scripts():
    # Get all Python scripts in the commands directory
    commands_dir = 'commands'
    if not os.path.isdir(commands_dir):
        print(f"Error: Commands directory '{commands_dir}' not found.")
        return
        
    # Create output directory
    os.makedirs('bin', exist_ok=True)
    
    # Get list of Python scripts in commands directory
    scripts = glob.glob(os.path.join(commands_dir, '*.py'))
    
    if not scripts:
        print("No Python scripts found to compile.")
        return
    
    # Compile each script
    for script in scripts:
        print(f"Compiling {script}...")
        
        # Get the output binary name (without .py extension and path)
        binary_name = os.path.basename(script)
        binary_name = os.path.splitext(binary_name)[0]
        
        # Run PyInstaller
        try:
            subprocess.run([
                'pyinstaller',
                '--onefile',
                '--clean',
                '--distpath=bin',
                f'--name={binary_name}',
                script
            ], check=True)
            
            print(f"Successfully compiled {binary_name}")
        except subprocess.CalledProcessError as e:
            print(f"Error compiling {script}: {e}", file=sys.stderr)

if __name__ == "__main__":
    compile_scripts()
"""
    
    # Write the compilation script
    with open("compile_binaries.py", "w") as f:
        f.write(compile_script)
    
    # Make it executable
    os.chmod("compile_binaries.py", 0o755)
    
    print("\nSetup complete!")
    print("To compile the Python scripts into binaries, run:")
    print("  python compile_binaries.py")
    print("\nThe compiled binaries will be placed in a 'bin' directory.")

if __name__ == "__main__":
    main() 