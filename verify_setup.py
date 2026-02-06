#!/usr/bin/env python3
"""
Setup verification script for Null-Code-Analyzer
Run this after installation to verify everything works
"""

import sys
import subprocess
from pathlib import Path


def print_header(text):
    """Print section header"""
    print(f"\n{'=' * 70}")
    print(f"  {text}")
    print('=' * 70)


def check_python_version():
    """Verify Python 3.10+"""
    print_header("Checking Python Version")
    
    version = sys.version_info
    print(f"Python {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 10):
        print("❌ ERROR: Python 3.10+ required")
        return False
    
    print("✓ Python version OK")
    return True


def check_installation():
    """Verify nullcode is installed"""
    print_header("Checking Installation")
    
    try:
        result = subprocess.run(
            ["nullcode", "--help"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            print("✓ nullcode command available")
            return True
        else:
            print("❌ ERROR: nullcode command failed")
            return False
            
    except FileNotFoundError:
        print("❌ ERROR: nullcode command not found")
        print("\nRun: pip install -e .")
        return False
    except subprocess.TimeoutExpired:
        print("❌ ERROR: Command timeout")
        return False


def check_dependencies():
    """Check if key dependencies are installed"""
    print_header("Checking Dependencies")
    
    required = [
        "torch",
        "transformers",
        "rich",
        "typer",
        "tqdm"
    ]
    
    all_ok = True
    
    for package in required:
        try:
            __import__(package)
            print(f"✓ {package}")
        except ImportError:
            print(f"❌ {package} not installed")
            all_ok = False
    
    if not all_ok:
        print("\nRun: pip install -e .")
    
    return all_ok


def check_directory_structure():
    """Verify project structure"""
    print_header("Checking Directory Structure")
    
    required_dirs = [
        "nullcode",
        "nullcode/core",
        "nullcode/ui",
        "nullcode/languages",
        "nullcode/utils",
        "tests/fixtures"
    ]
    
    all_ok = True
    base_path = Path(__file__).parent
    
    for dir_path in required_dirs:
        full_path = base_path / dir_path
        if full_path.exists():
            print(f"✓ {dir_path}/")
        else:
            print(f"❌ {dir_path}/ missing")
            all_ok = False
    
    return all_ok


def run_test_scan():
    """Run a test scan on fixtures"""
    print_header("Running Test Scan")
    
    fixtures_path = Path(__file__).parent / "tests" / "fixtures"
    
    if not fixtures_path.exists():
        print("❌ Test fixtures not found")
        return False
    
    try:
        print("\nScanning test fixtures (this may take a moment)...\n")
        
        result = subprocess.run(
            [
                "nullcode", "scan",
                str(fixtures_path),
                "--mode", "quick",
                "--i-accept-ethics",
                "--ci"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # CI mode returns 1 if vulnerabilities found (expected!)
        if result.returncode in [0, 1]:
            print("✓ Test scan completed successfully")
            print(f"\nOutput preview:")
            print(result.stdout[:500])
            return True
        else:
            print(f"❌ Test scan failed with code {result.returncode}")
            print(result.stderr)
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Test scan timeout (>30s)")
        return False
    except Exception as e:
        print(f"❌ Test scan error: {e}")
        return False


def main():
    """Run all verification checks"""
    print("""
    ███╗   ██╗██╗   ██╗██╗     ██╗      ██████╗ ██████╗ ██████╗ ███████╗
    ████╗  ██║██║   ██║██║     ██║     ██╔════╝██╔═══██╗██╔══██╗██╔════╝
    ██╔██╗ ██║██║   ██║██║     ██║     ██║     ██║   ██║██║  ██║█████╗  
    ██║╚██╗██║██║   ██║██║     ██║     ██║     ██║   ██║██║  ██║██╔══╝  
    ██║ ╚████║╚██████╔╝███████╗███████╗╚██████╗╚██████╔╝██████╔╝███████╗
    ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
    
    Setup Verification Script
    """)
    
    checks = [
        ("Python Version", check_python_version),
        ("Installation", check_installation),
        ("Dependencies", check_dependencies),
        ("Directory Structure", check_directory_structure),
        ("Test Scan", run_test_scan)
    ]
    
    results = []
    
    for name, check_func in checks:
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ {name} check failed with error: {e}")
            results.append((name, False))
    
    # Summary
    print_header("Verification Summary")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    print(f"\n{passed}/{total} checks passed")
    
    if passed == total:
        print("\n🎉 All checks passed! Null-Code-Analyzer is ready to use.")
        print("\nNext steps:")
        print("  1. Read QUICKSTART.md for usage examples")
        print("  2. Review ETHICS.md for legal guidelines")
        print("  3. Run: nullcode scan ./your-project --i-accept-ethics")
        return 0
    else:
        print("\n⚠️  Some checks failed. Please fix the issues above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
