#!/bin/bash
# Quick one-liner to complete setup and run first test

echo "🚀 Null-Code-Analyzer - Quick Setup"
echo ""

# Activate venv
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Run these first:"
    echo "   python3 -m venv venv"
    echo "   source venv/bin/activate"
    echo "   pip install torch transformers rich typer semgrep tqdm"
    exit 1
fi

source venv/bin/activate

# Install package
echo "Installing nullcode..."
pip install -e . --quiet

# Quick test
echo ""
echo "Testing installation..."
nullcode --help > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✓ nullcode command is working"
else
    echo "❌ Installation failed"
    exit 1
fi

# Check Semgrep
if command -v semgrep &> /dev/null; then
    echo "✓ Semgrep available (hybrid mode enabled)"
else
    echo "⚠ Semgrep not found (AI-only mode)"
fi

echo ""
echo "🎉 Setup complete! Try this:"
echo ""
echo "   nullcode scan tests/fixtures/ --i-accept-ethics"
echo ""
