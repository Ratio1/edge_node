# Edge Node Command Binaries

This directory contains the command scripts for controlling and monitoring edge nodes. All scripts have been converted to Python and can be compiled into protected binaries.

## Directory Structure

- `commands/`: Directory containing all Python command scripts
- `bin/`: Contains the compiled binary versions of commands (created during compilation)
- Setup scripts in root directory:
  - `setup_compilation.py`: Installs required dependencies
  - `compile_binaries.py`: Compiles the Python scripts into binaries
  - `install_binaries.py`: Installs compiled binaries to a target directory
  - `build_in_docker.sh`: Builds binaries in a Docker container (recommended method)

## Converted Commands

All edge node management commands have been converted to Python and placed in the `commands/` directory:

| Command | Description |
|---------|-------------|
| add_allowed.py | Add an address to authorized addresses |
| change_alias.py | Change the node alias |
| get_allowed.py | Display authorized addresses |
| get_config_app.py | Get application configuration |
| get_e2_pem_file.py | Display node authentication file |
| get_node_history.py | Display node history |
| get_node_info.py | Display node information |
| get_startup_config.py | Display startup configuration |
| reset_address.py | Reset node address |
| reset_node_keys.py | Reset node keys |
| reset_supervisor.py | Reset supervisor |
| update_allowed_batch.py | Update authorized addresses in batch |

## Compiling and Installing Binaries

### Recommended Method: Using Docker (Recommended)

This is the preferred method as it ensures binaries are built with the same Ubuntu/GLIBC version as the target environment.

1. Run the Docker build script:
   ```
   ./build_in_docker.sh
   ```

2. The compiled binaries will be available in the `bin/` directory and will be compatible with the target Ubuntu environment.

### Alternative Method: Direct Compilation

If you prefer to compile directly on your system:

#### Prerequisites

- Python 3.6+
- pip (Python package manager)

#### Steps to Compile

1. Run the setup script from the root directory:
   ```
   python setup_compilation.py
   ```

2. Compile all Python scripts to binaries:
   ```
   python compile_binaries.py
   ```

3. The compiled binaries will be available in the `bin/` directory.

### Installing Binaries

To install the compiled binaries to a target directory:

```
python install_binaries.py <target_directory>
```

For example, to install to a local bin directory:

```
python install_binaries.py /usr/local/bin
```

For Docker integration, you can install the binaries during the Docker build process:

```dockerfile
COPY cmds/bin/* /usr/local/bin/
```

## Compilation Details

- PyInstaller is used to create standalone executables
- Each binary is compiled with `--onefile` option for a single, self-contained executable
- When using `build_in_docker.sh`, binaries are built with the same Ubuntu/GLIBC version as the target environment
- The binaries can be directly copied to Docker images
- Source code is protected from inspection

## Binary Usage

The compiled binaries can be used the same way as the original scripts:

```
docker exec <container> add_allowed <node-address> [alias]
docker exec <container> get_node_info
```

## Adding New Commands

1. Create a new Python script in the `commands/` directory
2. Run the compilation script to create the binary
3. Use the installation script to copy the binary to the target location

## Security Considerations

- Binary compilation helps protect source code but is not 100% secure
- Consider additional protection mechanisms for sensitive commands
- Implement proper authentication and authorization in the edge node logic 