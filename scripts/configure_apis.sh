#!/bin/bash

# Script to configure API keys for various security tools

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

configure_shodan() {
    echo ""
    print_info "=== Configuring Shodan API ==="

    if [ -f "$HOME/.shodan/api_key" ]; then
        print_warning "Shodan API key already configured"
        echo -n "Overwrite? (y/n): "
        read -r overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            return
        fi
    fi

    echo -n "Enter your Shodan API key: "
    read -r api_key

    if [ -z "$api_key" ]; then
        print_warning "No API key provided, skipping..."
        return
    fi

    shodan init "$api_key"

    if shodan info &>/dev/null; then
        print_success "Shodan API key configured and verified!"
    else
        print_warning "API key saved but verification failed. Please check your key."
    fi
}

configure_subfinder() {
    echo ""
    print_info "=== Configuring Subfinder API Keys ==="

    mkdir -p ~/.config/subfinder

    if [ -f "$HOME/.config/subfinder/provider-config.yaml" ]; then
        print_warning "Subfinder config already exists"
        echo -n "Edit existing config? (y/n): "
        read -r edit
        if [[ "$edit" =~ ^[Yy]$ ]]; then
            ${EDITOR:-nano} ~/.config/subfinder/provider-config.yaml
        fi
        return
    fi

    cat > ~/.config/subfinder/provider-config.yaml <<EOF
# Subfinder Provider Configuration
# Add your API keys here for better results

# Shodan (already configured separately, but can add here too)
# shodan: ["YOUR_SHODAN_API_KEY"]

# Censys
# censys: ["YOUR_CENSYS_API_ID:YOUR_CENSYS_API_SECRET"]

# VirusTotal
# virustotal: ["YOUR_VIRUSTOTAL_API_KEY"]

# GitHub (Personal Access Token)
# github: ["YOUR_GITHUB_TOKEN"]

# Chaos (ProjectDiscovery)
# chaos: ["YOUR_CHAOS_API_KEY"]

# SecurityTrails
# securitytrails: ["YOUR_SECURITYTRAILS_API_KEY"]

# Uncomment and add your keys above
EOF

    print_success "Subfinder config template created at ~/.config/subfinder/provider-config.yaml"
    print_info "Edit the file to add your API keys"

    echo -n "Open config file now? (y/n): "
    read -r open
    if [[ "$open" =~ ^[Yy]$ ]]; then
        ${EDITOR:-nano} ~/.config/subfinder/provider-config.yaml
    fi
}

create_env_template() {
    echo ""
    print_info "=== Creating .env Template ==="

    if [ -f ".env" ]; then
        print_warning ".env file already exists"
        return
    fi

    cat > .env <<EOF
# Asset Monitor Configuration

# Shodan API Key (required for port scanning and vulnerability detection)
SHODAN_API_KEY=your_shodan_api_key_here

# Notification Channels (optional)
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Database
DATABASE_URL=sqlite:///./assetmon.db

# Scan Configuration
SCAN_THREADS=50
DNS_RATE_LIMIT=100
HTTP_TIMEOUT=10

# Tool Paths (leave empty to use PATH)
SUBFINDER_PATH=
DNSX_PATH=
HTTPX_PATH=
GAU_PATH=
KATANA_PATH=
EOF

    print_success ".env template created"
    print_info "Edit .env file to add your configuration"
}

main() {
    echo "=========================================="
    echo "  API Keys Configuration"
    echo "=========================================="

    echo ""
    echo "This script will help you configure API keys for:"
    echo "  1. Shodan (required)"
    echo "  2. Subfinder providers (optional but recommended)"
    echo "  3. Create .env template for the platform"
    echo ""

    # Shodan
    echo -n "Configure Shodan API key? (y/n): "
    read -r config_shodan
    if [[ "$config_shodan" =~ ^[Yy]$ ]]; then
        configure_shodan
    fi

    # Subfinder
    echo -n "Configure Subfinder API keys? (y/n): "
    read -r config_subfinder
    if [[ "$config_subfinder" =~ ^[Yy]$ ]]; then
        configure_subfinder
    fi

    # .env template
    create_env_template

    echo ""
    echo "=========================================="
    print_success "Configuration complete!"
    echo ""
    print_info "Next steps:"
    echo "  1. Edit .env file with your API keys and preferences"
    echo "  2. Run verify_tools.sh to check everything is working"
    echo "  3. Start using the asset monitoring platform"
    echo "=========================================="
}

main "$@"
