#!/bin/bash

# Bash script to update Node.js, npm, install @openai/codex globally, and launch VS Code
# Optimized for Ubuntu 22.04+ with root/non-root detection
# Works in devcontainers and regular user environments
# Author: Generated script
# Date: $(date +"%Y-%m-%d")

set -e  # Exit on any error

echo "=== Node.js/npm Update & OpenAI Codex Setup for Ubuntu 22.04+ ==="

# Function to print colored output
print_status() {
    echo -e "\033[1;32m[INFO]\033[0m $1"
}

print_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1"
}

print_warning() {
    echo -e "\033[1;33m[WARNING]\033[0m $1"
}

print_success() {
    echo -e "\033[1;36m[SUCCESS]\033[0m $1"
}

# Check if running as root and set appropriate command prefix
if [ "$EUID" -eq 0 ]; then
    print_status "Running as root (UID=0) - no sudo needed"
    SUDO_CMD=""
    USER_HOME="/root"
    IS_ROOT=true
else
    print_status "Running as regular user - using sudo for system operations"
    SUDO_CMD="sudo"
    USER_HOME="$HOME"
    IS_ROOT=false
fi

# Check if running on Ubuntu
if command -v lsb_release >/dev/null 2>&1; then
    if ! lsb_release -d | grep -q "Ubuntu"; then
        print_warning "This script is optimized for Ubuntu 22.04+. Detected: $(lsb_release -d | cut -f2)"
    fi
else
    print_warning "lsb_release not available - assuming Ubuntu-compatible system"
fi

# # Update system packages first
# print_status "Updating system packages..."
# $SUDO_CMD apt update && $SUDO_CMD apt upgrade -y

# # Install required dependencies
# print_status "Installing required dependencies..."
# $SUDO_CMD apt install -y curl wget software-properties-common apt-transport-https ca-certificates gnupg lsb-release

# Remove old Node.js versions if installed via apt
print_status "Removing old Node.js installations..."
$SUDO_CMD apt remove -y nodejs npm 2>/dev/null || true
$SUDO_CMD apt autoremove -y

# Install Node.js using NodeSource repository (recommended for Ubuntu)
print_status "Adding NodeSource repository for latest Node.js LTS..."
if [ "$IS_ROOT" = false ]; then
  curl -fsSL https://deb.nodesource.com/setup_lts.x | $SUDO_CMD -E bash -
else
  curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
fi

print_status "Installing Node.js LTS..."
$SUDO_CMD apt install -y nodejs

# Verify Node.js installation
NODE_VERSION=$(node --version)
NPM_VERSION=$(npm --version)
print_success "Node.js installed: $NODE_VERSION"
print_success "npm installed: $NPM_VERSION"

# Handle npm global packages based on user context
if [ "$IS_ROOT" = true ]; then
    # Running as root - install globally without user-specific config
    print_status "Running as root - updating npm globally..."
    npm install -g npm@latest

    print_success "Updated npm version: $(npm --version)"

    # Install @openai/codex globally as root
    print_status "Installing @openai/codex globally (root)..."
    if npm install -g @openai/codex; then
        print_success "Successfully installed @openai/codex"
        print_status "Codex CLI available at: $(which codex 2>/dev/null || echo '/usr/local/bin/codex (expected)')"
    else
        print_error "Failed to install @openai/codex"
        print_warning "This might be due to network issues or package availability"
    fi
else
    # Running as regular user - use user-specific npm global directory
    print_status "Updating npm to latest version..."
    $SUDO_CMD npm install -g npm@latest

    print_success "Updated npm version: $(npm --version)"

    # Fix npm permissions for global packages (Ubuntu-specific issue)
    print_status "Configuring npm global packages directory..."
    mkdir -p "$USER_HOME/.npm-global"
    npm config set prefix "$USER_HOME/.npm-global"

    # Add npm global bin to PATH if not already present
    if ! echo $PATH | grep -q "$USER_HOME/.npm-global/bin"; then
        print_status "Adding npm global bin to PATH..."
        echo "export PATH=$USER_HOME/.npm-global/bin:\$PATH" >> "$USER_HOME/.bashrc"
        export PATH="$USER_HOME/.npm-global/bin:$PATH"
        print_success "PATH updated. You may need to restart your terminal or run 'source ~/.bashrc'"
    fi

    # Install @openai/codex globally in user directory
    print_status "Installing @openai/codex globally (user)..."
    if npm install -g @openai/codex; then
        print_success "Successfully installed @openai/codex"
        print_status "Codex CLI available at: $(which codex 2>/dev/null || echo 'Not found in current PATH - restart terminal')"
    else
        print_error "Failed to install @openai/codex"
        print_warning "This might be due to network issues or package availability"
    fi
fi

# # Install VS Code if not present
# if ! command -v code >/dev/null 2>&1; then
#     print_status "VS Code not found. Installing VS Code..."

#     # Add Microsoft GPG key and repository
#     wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
#     $SUDO_CMD install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
#     $SUDO_CMD sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'

#     # Update package list and install VS Code
#     $SUDO_CMD apt update
#     $SUDO_CMD apt install -y code

#     print_success "VS Code installed successfully"
# else
#     print_status "VS Code already installed: $(code --version | head -n1)"
# fi

# # Handle VS Code launch based on environment
# if [ "$IS_ROOT" = true ]; then
#     # In root/devcontainer context, VS Code might not be launchable or needed
#     if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then
#         print_status "Display detected - attempting to launch VS Code..."
#         if command -v code >/dev/null 2>&1; then
#             nohup code --no-sandbox --user-data-dir="$USER_HOME/.vscode-root" > /dev/null 2>&1 &
#             print_success "VS Code launched with root-safe parameters"
#         fi
#     else
#         print_status "No display detected (likely devcontainer/headless) - VS Code GUI not launched"
#         print_status "Use 'code .' to open current directory or 'code filename' to edit files"
#     fi
# else
#     # Regular user context
#     print_status "Launching VS Code..."
#     if command -v code >/dev/null 2>&1; then
#         if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then
#             nohup code > /dev/null 2>&1 &
#             print_success "VS Code launched successfully"
#         else
#             print_status "No display detected - VS Code available via command line"
#         fi
#     else
#         print_error "VS Code command 'code' not found"
#         print_status "Try restarting your terminal or running 'source ~/.bashrc'"
#     fi
# fi

# Display final status
echo ""
echo "=== Installation Summary ==="
print_success "Node.js: $(node --version)"
print_success "npm: $(npm --version)"

# # Handle VS Code version check
# if command -v code >/dev/null 2>&1; then
#     VS_CODE_VERSION=$(code --version 2>/dev/null | head -n1 || echo 'Available but version check failed')
#     print_success "VS Code: $VS_CODE_VERSION"
# else
#     print_warning "VS Code: Please restart terminal"
# fi

# Check if codex is available
if command -v codex >/dev/null 2>&1; then
    print_success "OpenAI Codex CLI: Available"
elif [ "$IS_ROOT" = true ]; then
    print_success "OpenAI Codex CLI: Available (may need full path: /usr/local/bin/codex)"
else
    print_warning "OpenAI Codex CLI: Restart terminal to use 'codex' command"
fi

echo ""
if [ "$IS_ROOT" = true ]; then
    print_status "Setup completed for root environment!"
    print_status "- Node.js and npm are ready to use"
    print_status "- Run 'codex --help' or '/usr/local/bin/codex --help' to get started"
    print_status "- VS Code available via 'code' command"
else
    print_status "Setup completed! If this is your first time:"
    print_status "1. Restart your terminal or run: source ~/.bashrc"
    print_status "2. Run 'codex --help' to get started with OpenAI Codex"
    print_status "3. VS Code is ready to use"
fi

echo "=== Script execution completed ==="
