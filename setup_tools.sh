#!/bin/bash

# Asset Monitor - Automated Tools Installation Script
# This script will check and install all required security tools

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

# Main installation functions
install_go() {
    print_info "Installing Go..."

    if check_command go; then
        GO_VERSION=$(go version | awk '{print $3}')
        print_success "Go already installed: $GO_VERSION"
        return 0
    fi

    GO_VERSION="1.21.5"
    GO_ARCH="linux-amd64"
    GO_URL="https://go.dev/dl/go${GO_VERSION}.${GO_ARCH}.tar.gz"

    print_info "Downloading Go ${GO_VERSION}..."
    wget -q --show-progress "${GO_URL}" -O /tmp/go.tar.gz

    print_info "Installing Go to /usr/local/go..."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz

    # Setup Go environment
    if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi

    if ! grep -q "GOPATH" ~/.bashrc; then
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    fi

    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin

    print_success "Go installed successfully"
}

install_go_tool() {
    local tool_name=$1
    local install_path=$2
    local version_flag=${3:--version}

    if check_command "$tool_name"; then
        print_success "$tool_name already installed"
        return 0
    fi

    print_info "Installing $tool_name..."
    go install -v "$install_path" 2>&1 | grep -v "go: downloading" || true

    if check_command "$tool_name"; then
        print_success "$tool_name installed successfully"
    else
        print_error "$tool_name installation failed"
        return 1
    fi
}

install_python_deps() {
    print_info "Installing Python dependencies..."

    if ! check_command pip3 && ! check_command pip; then
        print_error "pip not found. Installing python3-pip..."
        sudo apt install -y python3-pip
    fi

    # Install shodan
    if ! python3 -c "import shodan" 2>/dev/null; then
        print_info "Installing shodan Python package..."
        pip3 install shodan
        print_success "Shodan installed successfully"
    else
        print_success "Shodan already installed"
    fi
}

# Main script
main() {
    echo "=========================================="
    echo "  Asset Monitor - Tools Setup"
    echo "=========================================="
    echo ""

    # Check if running on Linux
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        print_warning "This script is designed for Linux. Continue anyway? (y/n)"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Update package list
    print_info "Updating package list..."
    sudo apt update -qq

    # Install prerequisites
    print_info "Installing prerequisites..."
    sudo apt install -y wget curl git build-essential python3-pip >/dev/null 2>&1
    print_success "Prerequisites installed"
    
    # Install weasyprint dependencies (for PDF report generation)
    print_info "Installing PDF report dependencies (weasyprint)..."
    sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev >/dev/null 2>&1
    pip3 install weasyprint >/dev/null 2>&1
    print_success "PDF report dependencies installed"
    
    # Install Chromium (for httpx screenshot functionality)
    print_info "Installing Chromium (for screenshots)..."
    if check_command chromium-browser || check_command chromium; then
        print_success "Chromium already installed"
    else
        sudo apt install -y chromium-browser >/dev/null 2>&1 || sudo apt install -y chromium >/dev/null 2>&1
        if check_command chromium-browser || check_command chromium; then
            print_success "Chromium installed successfully"
        else
            print_warning "Chromium installation failed - screenshots may not work"
        fi
    fi
    echo ""

    # Install Go
    echo "=== Installing Go ==="
    install_go
    echo ""

    # Make sure Go paths are available in current session
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin

    # Install Go-based tools
    echo "=== Installing Security Tools ==="

    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
    install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest"
    install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau@latest"
    install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana@latest"
    install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

    # Optional: Amass (commented out by default as it's heavy)
    # print_info "Install Amass? (heavy tool, takes time) (y/n)"
    # read -r response
    # if [[ "$response" =~ ^[Yy]$ ]]; then
    #     install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master"
    # fi

    echo ""

    # Install Python tools
    echo "=== Installing Python Tools ==="
    install_python_deps
    echo ""

    # Verify installations
    echo "=== Verifying Installations ==="
    echo ""

    tools=(
        "go:version"
        "subfinder:-version"
        "assetfinder:-h"
        "dnsx:-version"
        "httpx:-version"
        "waybackurls:-h"
        "gau:-version"
        "katana:-version"
        "shodan:info"
    )

    failed_tools=()

    for tool_info in "${tools[@]}"; do
        IFS=':' read -r tool flag <<< "$tool_info"

        if check_command "$tool"; then
            version_output=$($tool $flag 2>&1 | head -n 1 | tr -d '\n')
            print_success "$tool is ready - $version_output"
        else
            print_error "$tool is NOT installed"
            failed_tools+=("$tool")
        fi
    done

    echo ""
    echo "=========================================="

    if [ ${#failed_tools[@]} -eq 0 ]; then
        print_success "All tools installed successfully!"
        echo ""
        print_info "Next steps:"
        echo "  1. Reload your shell: source ~/.bashrc"
        echo "  2. Configure Shodan API: shodan init YOUR_API_KEY"
        echo "  3. (Optional) Configure subfinder API keys in ~/.config/subfinder/provider-config.yaml"
        echo ""
        print_info "You can verify tools anytime by running:"
        echo "  ./verify_tools.sh"
    else
        print_warning "Some tools failed to install:"
        for tool in "${failed_tools[@]}"; do
            echo "  - $tool"
        done
        echo ""
        print_info "Try running the script again or install manually"
        exit 1
    fi

    echo "=========================================="
}

# Run main function
main "$@"
