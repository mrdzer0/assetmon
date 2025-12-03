#!/bin/bash

# Quick verification script for all installed tools

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_check() {
    local tool=$1
    local flag=$2

    if command -v "$tool" &> /dev/null; then
        version=$($tool $flag 2>&1 | head -n 1 | cut -c 1-60)
        echo -e "${GREEN}✓${NC} $tool: $version"
    else
        echo -e "${RED}✗${NC} $tool: NOT INSTALLED"
    fi
}

echo "=== Tool Verification ==="
echo ""

print_check "go" "version"
print_check "subfinder" "-version"
print_check "assetfinder" "-h"
print_check "dnsx" "-version"
print_check "httpx" "-version"
print_check "waybackurls" "-h"
print_check "gau" "-version"
print_check "katana" "-version"

echo ""
echo "=== Python Tools ==="
if python3 -c "import shodan" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} shodan python package"
else
    echo -e "${RED}✗${NC} shodan python package: NOT INSTALLED"
fi

echo ""
echo "=== Shodan API Configuration ==="
if [ -f "$HOME/.shodan/api_key" ]; then
    echo -e "${GREEN}✓${NC} Shodan API key configured"
    shodan info 2>/dev/null || echo -e "${YELLOW}!${NC} API key found but might be invalid"
else
    echo -e "${YELLOW}!${NC} Shodan API key not configured yet"
    echo "  Run: shodan init YOUR_API_KEY"
fi

echo ""
