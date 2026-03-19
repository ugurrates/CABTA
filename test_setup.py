#!/usr/bin/env python3
"""
Blue Team Assistant - Setup Verification Script

This script verifies that all dependencies are installed correctly.

Author: Ugur Ates
"""

import sys
import importlib

def check_dependency(module_name: str, package_name: str = None) -> bool:
    """Check if a Python module is installed."""
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        return False

def main():
    print("=" * 60)
    print("Blue Team Assistant - Setup Verification")
    print("=" * 60)
    print()

    # Required dependencies
    dependencies = [
        ("requests", "requests"),
        ("yaml", "pyyaml"),
        ("pefile", "pefile"),
        ("yara", "yara-python"),
        ("ssdeep", "ssdeep"),
        ("magic", "python-magic"),
        ("oletools.olevba", "oletools"),
        ("email", None),  # Built-in
        ("zipfile", None),  # Built-in
    ]

    # Optional dependencies
    optional = [
        ("capa", "capa"),
        ("anthropic", "anthropic"),
        ("openai", "openai"),
    ]

    print("Required Dependencies:")
    print("-" * 40)
    
    all_ok = True
    for module, package in dependencies:
        status = "✅" if check_dependency(module) else "❌"
        if not check_dependency(module) and package:
            all_ok = False
        print(f"  {status} {module}")

    print()
    print("Optional Dependencies:")
    print("-" * 40)
    
    for module, package in optional:
        status = "✅" if check_dependency(module) else "⚠️"
        print(f"  {status} {module}")

    print()
    print("=" * 60)
    
    if all_ok:
        print("✅ All required dependencies are installed!")
        print()
        print("Quick Start:")
        print("  python -m src.soc_agent ioc 8.8.8.8")
        print("  python -m src.soc_agent file malware.exe")
        print("  python -m src.soc_agent email suspicious.eml")
    else:
        print("❌ Some dependencies are missing!")
        print()
        print("Install with: pip install -r requirements.txt")
        sys.exit(1)

if __name__ == "__main__":
    main()
