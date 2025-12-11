#!/bin/bash

# Asset Monitor - Setup Validation Script

echo "🔍 Checking Asset Monitor Setup..."
echo ""

ERRORS=0
WARNINGS=0

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo "✓ Python: $PYTHON_VERSION"
else
    echo "✗ Python 3 not found"
    ERRORS=$((ERRORS+1))
fi

# Check database
if [ -f "assetmon.db" ]; then
    SIZE=$(du -h assetmon.db | awk '{print $1}')
    echo "✓ Database: assetmon.db ($SIZE)"
else
    echo "⚠ Database not initialized yet (will be created on first run)"
fi

# Check .env
if [ -f ".env" ]; then
    echo "✓ Config: .env file exists"

    # Check for Shodan API key
    if grep -q "SHODAN_API_KEY=your_shodan" .env 2>/dev/null || grep -q "SHODAN_API_KEY=$" .env 2>/dev/null; then
        echo "  ⚠ Shodan API key not configured (optional)"
        WARNINGS=$((WARNINGS+1))
    fi
else
    echo "⚠ Config: .env not found (copy from .env.example)"
    WARNINGS=$((WARNINGS+1))
fi

# Check Python packages
echo ""
echo "Checking Python dependencies..."

PACKAGES=(
    "fastapi"
    "uvicorn"
    "sqlalchemy"
    "pydantic"
    "requests"
    "click"
    "apscheduler"
    "jinja2"
    "aiofiles"
    "python_multipart"
    "weasyprint"
)

for pkg in "${PACKAGES[@]}"; do
    # Handle package name with underscore for import
    import_name=$(echo "$pkg" | tr '-' '_')
    if python3 -c "import $import_name" 2>/dev/null; then
        echo "  ✓ $pkg"
    else
        echo "  ✗ $pkg (run: pip install -r requirements.txt)"
        ERRORS=$((ERRORS+1))
    fi
done

# Check CLI tools
echo ""
echo "Checking CLI tools..."

TOOLS=(
    "subfinder"
    "assetfinder"
    "dnsx"
    "httpx"
    "waybackurls"
    "gau"
    "katana"
    "naabu"
    "nuclei"
)

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "  ✓ $tool"
    else
        echo "  ⚠ $tool not found (run: ./setup_tools.sh)"
        WARNINGS=$((WARNINGS+1))
    fi
done

# Check Chromium for screenshots
echo ""
echo "Checking screenshot support..."
if command -v chromium-browser &> /dev/null || command -v chromium &> /dev/null; then
    echo "  ✓ Chromium installed (screenshots supported)"
else
    echo "  ⚠ Chromium not found (screenshots disabled)"
    WARNINGS=$((WARNINGS+1))
fi

# Check shodan CLI
echo ""
echo "Checking Shodan..."
if command -v shodan &> /dev/null; then
    echo "  ✓ shodan CLI"
else
    echo "  ⚠ shodan CLI not found (install: pip install shodan)"
    WARNINGS=$((WARNINGS+1))
fi

if python3 -c "import shodan" 2>/dev/null; then
    echo "  ✓ shodan Python package"
else
    echo "  ⚠ shodan Python package not installed"
    WARNINGS=$((WARNINGS+1))
fi

echo ""
echo "=========================================="

if [ $ERRORS -eq 0 ]; then
    if [ $WARNINGS -eq 0 ]; then
        echo "✅ All checks passed! Ready to start."
    else
        echo "✅ Setup complete with $WARNINGS optional warnings."
    fi
    echo ""
    echo "To start the web server:"
    echo "  ./start_web.sh"
    echo ""
    echo "To use CLI tools:"
    echo "  python3 cli.py --help"
else
    echo "⚠️  Found $ERRORS critical issues"
    echo ""
    echo "Fix them by running:"
    echo "  pip install -r requirements.txt"
    echo "  ./setup_tools.sh"
fi

echo "=========================================="
