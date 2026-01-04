#!/bin/bash
# API Endpoint Hunter - Setup Script

set -e

echo "🔍 API Endpoint Hunter - Setup"
echo "==============================="
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.10"

echo "Checking Python version..."
if [[ "$PYTHON_VERSION" < "$REQUIRED_VERSION" ]]; then
    echo "❌ Python $REQUIRED_VERSION or higher is required (found $PYTHON_VERSION)"
    exit 1
fi
echo "✓ Python $PYTHON_VERSION detected"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo ""
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate
echo "✓ Virtual environment activated"

# Install dependencies
echo ""
echo "Installing Python dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "✓ Dependencies installed"

# Install Playwright browsers
echo ""
echo "Installing Playwright browsers (this may take a minute)..."
playwright install chromium
echo "✓ Chromium browser installed"

echo ""
echo "==============================="
echo "✨ Setup complete!"
echo ""
echo "To get started:"
echo "  1. Activate the virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run the hunter:"
echo "     python hunter.py crawl https://example.com"
echo ""
echo "For help:"
echo "     python hunter.py --help"
echo "==============================="
