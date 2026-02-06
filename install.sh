#!/bin/bash
# Complete setup script for Null-Code-Analyzer
# Run this after activating your virtual environment

set -e  # Exit on error

echo "========================================================================"
echo "  NULL-CODE-ANALYZER - Complete Setup"
echo "========================================================================"
echo ""

# Check if virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    echo "❌ ERROR: Virtual environment not activated"
    echo ""
    echo "Run this first:"
    echo "  source venv/bin/activate"
    echo ""
    exit 1
fi

echo "✓ Virtual environment: $VIRTUAL_ENV"
echo ""

# Step 1: Install package in editable mode
echo "Step 1: Installing nullcode package..."
pip install -e . --quiet
echo "✓ Package installed"
echo ""

# Step 2: Verify command is available
echo "Step 2: Verifying nullcode command..."
if command -v nullcode &> /dev/null; then
    echo "✓ nullcode command is available"
else
    echo "❌ nullcode command not found after installation"
    exit 1
fi
echo ""

# Step 3: Check Semgrep
echo "Step 3: Checking Semgrep availability..."
if command -v semgrep &> /dev/null; then
    SEMGREP_VERSION=$(semgrep --version 2>&1 | head -n1)
    echo "✓ Semgrep installed: $SEMGREP_VERSION"
    echo "  Hybrid mode (AI + Semgrep) available for 92% coverage"
else
    echo "⚠ Semgrep not found in PATH"
    echo "  AI-only mode will be used (68% coverage)"
    echo "  To enable hybrid mode, ensure semgrep is installed:"
    echo "    pip install semgrep"
fi
echo ""

# Step 4: Create cache directory
echo "Step 4: Setting up cache directory..."
mkdir -p ~/.nullcode/models
echo "✓ Cache directory: ~/.nullcode/models"
echo ""

# Step 5: Run verification
echo "Step 5: Running verification tests..."
echo "========================================================================"
python verify_setup.py
VERIFY_EXIT=$?
echo ""

if [ $VERIFY_EXIT -eq 0 ]; then
    echo "========================================================================"
    echo "  🎉 SETUP COMPLETE!"
    echo "========================================================================"
    echo ""
    echo "Your scanner is ready. Try these commands:"
    echo ""
    echo "  # Test on vulnerable fixtures"
    echo "  nullcode scan tests/fixtures/ --i-accept-ethics"
    echo ""
    echo "  # Run functional tests"
    echo "  python test_scanner.py"
    echo ""
    echo "  # Scan your own code"
    echo "  nullcode scan /path/to/your/project --i-accept-ethics"
    echo ""
    echo "  # Download AI model for offline use (optional, ~480MB)"
    echo "  nullcode download-models"
    echo ""
    echo "Next steps:"
    echo "  1. Read QUICKSTART.md for detailed usage"
    echo "  2. Review ETHICS.md for legal compliance"
    echo "  3. Check test_scanner.py output for system status"
    echo ""
else
    echo "========================================================================"
    echo "  ⚠️  SETUP INCOMPLETE"
    echo "========================================================================"
    echo ""
    echo "Some verification checks failed. Please:"
    echo "  1. Review the error messages above"
    echo "  2. Check SETUP.md for troubleshooting"
    echo "  3. Ensure all dependencies are installed"
    echo ""
    exit 1
fi
