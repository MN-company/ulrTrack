#!/bin/bash
# Blackbird OSINT Auto-Installer
# Clones and sets up Blackbird for ulrTrack integration

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BLACKBIRD_DIR="$PROJECT_ROOT/blackbird"

echo "🕵️  Blackbird OSINT Auto-Installer"
echo "=================================="

# Check if already installed
if [ -d "$BLACKBIRD_DIR" ]; then
    echo "⚠️  Blackbird already installed at: $BLACKBIRD_DIR"
    read -p "Do you want to reinstall? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Installation cancelled."
        exit 0
    fi
    echo "🗑️  Removing old installation..."
    rm -rf "$BLACKBIRD_DIR"
fi

# Clone repository
echo "📥 Cloning Blackbird repository..."
cd "$PROJECT_ROOT"
git clone https://github.com/p1ngul1n0/blackbird.git

# Install dependencies
echo "📦 Installing Blackbird dependencies..."
cd "$BLACKBIRD_DIR"

# Check if virtual environment should be used
if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
    echo "🐍 Using project virtual environment..."
    source "$PROJECT_ROOT/venv/bin/activate"
fi

pip install -r requirements.txt --quiet

echo ""
echo "✅ Blackbird installed successfully!"
echo "📍 Location: $BLACKBIRD_DIR"
echo ""
echo "Test with: cd blackbird && python blackbird.py --username test"
