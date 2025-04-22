#!/usr/bin/env python3
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
    
    scripts = glob.glob(os.path.join(commands_dir, '*.py'))
    
    if not scripts:
        print("No Python scripts found to compile.")
        return
    
    # Create output directory
    os.makedirs('bin', exist_ok=True)
    
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
