#!/bin/bash

# Asset Monitor - Tool Verification Script

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
        return 0
    else
        echo -e "${RED}✗${NC} $tool: NOT INSTALLED"
        return 1
    fi
}

echo "=== Asset Monitor - Tool Verification ==="
echo ""

MISSING=0

echo "--- Core Tools ---"
print_check "go" "version" || MISSING=$((MISSING+1))
echo ""

echo "--- Subdomain Discovery ---"
print_check "subfinder" "-version" || MISSING=$((MISSING+1))
print_check "assetfinder" "-h" || MISSING=$((MISSING+1))
echo ""

echo "--- DNS & HTTP ---"
print_check "dnsx" "-version" || MISSING=$((MISSING+1))
print_check "httpx" "-version" || MISSING=$((MISSING+1))
echo ""

echo "--- Port Scanning ---"
print_check "naabu" "-version" || MISSING=$((MISSING+1))
echo ""

echo "--- Vulnerability Scanning ---"
print_check "nuclei" "-version" || MISSING=$((MISSING+1))
echo ""

echo "--- Endpoint Discovery ---"
print_check "waybackurls" "-h" || MISSING=$((MISSING+1))
print_check "gau" "-version" || MISSING=$((MISSING+1))
print_check "katana" "-version" || MISSING=$((MISSING+1))
echo ""

echo "--- Screenshot Support ---"
if command -v chromium-browser &> /dev/null; then
    echo -e "${GREEN}✓${NC} chromium-browser: installed"
elif command -v chromium &> /dev/null; then
    echo -e "${GREEN}✓${NC} chromium: installed"
else
    echo -e "${YELLOW}!${NC} chromium: NOT INSTALLED (screenshots disabled)"
fi
echo ""

echo "=== Python Tools ==="
if python3 -c "import shodan" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} shodan Python package"
else
    echo -e "${RED}✗${NC} shodan Python package: NOT INSTALLED"
    MISSING=$((MISSING+1))
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
echo "=========================================="
if [ $MISSING -eq 0 ]; then
    echo -e "${GREEN}All tools installed!${NC}"
else
    echo -e "${YELLOW}$MISSING tool(s) missing${NC}"
    echo "Run ./setup_tools.sh to install missing tools"
fi
echo "=========================================="
