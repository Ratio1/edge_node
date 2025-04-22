#!/bin/bash
# This script builds the binaries in a Docker container with the same
# Ubuntu/GLIBC version as the target deployment environment

# Determine Ubuntu version being used in the target container
# Change this to match your container's Ubuntu version (e.g., 22.04)
UBUNTU_VERSION="22.04"

echo "Building binaries in Ubuntu $UBUNTU_VERSION container..."

# Make sure we're in the root directory of the project
cd "$(dirname "$0")/.."

# Create a temporary Dockerfile for building
cat > Dockerfile.build << EOF
FROM ubuntu:$UBUNTU_VERSION

# Install Python and dependencies
RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-dev

# Set up working directory
WORKDIR /build

# Copy our Python scripts and setup files
COPY cmds/commands/ /build/commands/
COPY cmds/setup_compilation.py /build/
COPY cmds/compile_binaries.py /build/

# Install PyInstaller
RUN pip3 install pyinstaller

# Run the compilation
RUN python3 compile_binaries.py

# Create bin directory if it doesn't exist yet
RUN mkdir -p /build/bin

# Make the binaries executable (only if they exist)
RUN if [ -d "/build/bin" ] && [ "$(ls -A /build/bin)" ]; then chmod +x /build/bin/*; fi
EOF

# Build the Docker image
docker build -t edgenode-binary-builder -f Dockerfile.build .

# Create bin directory if it doesn't exist
mkdir -p cmds/bin

# Copy the binaries from the container
docker create --name temp-builder edgenode-binary-builder
docker cp temp-builder:/build/bin/. cmds/bin/
docker rm temp-builder

# Clean up
rm Dockerfile.build

echo "Build complete! Binaries are in the cmds/bin/ directory."
echo "These binaries should now be compatible with your target environment." 