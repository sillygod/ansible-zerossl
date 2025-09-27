#!/usr/bin/env python3
"""
Fix Coverage Issues Script

This script addresses common coverage-related issues including:
- Corrupted .coverage files
- Coverage database errors
- Incompatible coverage data
- Permission issues
"""

import os
import subprocess
import sys
from pathlib import Path


def clean_coverage_files(project_root: Path):
    """Clean all coverage-related files."""
    print("🧹 Cleaning coverage files...")

    # Remove coverage database files
    coverage_files = [
        ".coverage",
        ".coverage.*",
        "coverage.xml",
        "coverage.json"
    ]

    for pattern in coverage_files:
        for file_path in project_root.glob(pattern):
            try:
                file_path.unlink()
                print(f"   Removed: {file_path}")
            except FileNotFoundError:
                pass
            except PermissionError:
                print(f"   Permission denied: {file_path}")

    # Remove HTML coverage directory
    htmlcov_dir = project_root / "htmlcov"
    if htmlcov_dir.exists():
        import shutil
        shutil.rmtree(htmlcov_dir)
        print(f"   Removed: {htmlcov_dir}")

    print("✅ Coverage files cleaned")


def check_coverage_installation():
    """Check if coverage is properly installed."""
    print("🔍 Checking coverage installation...")

    try:
        import coverage
        print(f"   Coverage version: {coverage.__version__}")

        # Check pytest-cov
        import pytest_cov
        print(f"   Pytest-cov version: {pytest_cov.__version__}")

        print("✅ Coverage tools properly installed")
        return True
    except ImportError as e:
        print(f"❌ Coverage installation issue: {e}")
        return False


def test_coverage_functionality(project_root: Path):
    """Test basic coverage functionality."""
    print("🧪 Testing coverage functionality...")

    # Run a simple coverage test
    cmd = [
        sys.executable, "-m", "pytest",
        "tests/unit/test_api_client.py::TestZeroSSLAPIClientImproved::test_api_client_initialization_real",
        "--cov=plugins.module_utils.zerossl.api_client",
        "--cov-report=term",
        "-v", "-q"
    ]

    try:
        result = subprocess.run(cmd, cwd=project_root, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            print("✅ Coverage functionality working")
            return True
        else:
            print(f"❌ Coverage test failed:")
            print(f"   stdout: {result.stdout}")
            print(f"   stderr: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ Coverage test timed out")
        return False
    except Exception as e:
        print(f"❌ Coverage test error: {e}")
        return False


def fix_pytest_configuration(project_root: Path):
    """Fix pytest configuration for coverage."""
    print("⚙️ Checking pytest configuration...")

    pytest_ini = project_root / "pytest.ini"
    if not pytest_ini.exists():
        print("❌ pytest.ini not found")
        return False

    # Read current configuration
    with open(pytest_ini, 'r') as f:
        content = f.read()

    # Check for coverage settings
    if "--cov=" in content:
        print("✅ Coverage configuration found in pytest.ini")
        return True
    else:
        print("⚠️ Coverage configuration not found in pytest.ini")
        # Could add configuration here if needed
        return False


def provide_solutions():
    """Provide solutions for common coverage issues."""
    print("\n💡 Solutions for Coverage Issues:")
    print("=" * 40)

    solutions = [
        {
            "issue": "Corrupted .coverage file",
            "solution": "rm -f .coverage* && rm -rf htmlcov/"
        },
        {
            "issue": "Permission errors",
            "solution": "chmod 755 . && chmod 644 .coverage*"
        },
        {
            "issue": "Coverage not installed",
            "solution": "pip install coverage>=7.3.0 pytest-cov"
        },
        {
            "issue": "Module not found in coverage",
            "solution": "Ensure modules are imported in tests"
        },
        {
            "issue": "Database incompatibility",
            "solution": "Upgrade coverage: pip install --upgrade coverage pytest-cov"
        }
    ]

    for i, item in enumerate(solutions, 1):
        print(f"{i}. {item['issue']}:")
        print(f"   Solution: {item['solution']}")
        print()


def run_coverage_without_issues(project_root: Path):
    """Run coverage in a way that avoids common issues."""
    print("🚀 Running coverage without common issues...")

    # Method 1: Run without coverage first to ensure tests work
    print("   Step 1: Testing without coverage...")
    cmd_no_cov = [
        sys.executable, "-m", "pytest",
        "tests/component/",
        "-v", "--tb=short", "--disable-warnings"
    ]

    result = subprocess.run(cmd_no_cov, cwd=project_root, capture_output=True, text=True)
    if result.returncode != 0:
        print("❌ Tests failing without coverage - fix tests first")
        return False

    # Method 2: Run with coverage using explicit configuration
    print("   Step 2: Running with coverage...")
    cmd_with_cov = [
        sys.executable, "-m", "pytest",
        "tests/component/",
        "--cov=plugins.action",
        "--cov=plugins.module_utils",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov",
        "--cov-config=.coveragerc",  # Use explicit config if exists
        "-v", "--tb=short"
    ]

    # Remove --cov-config if .coveragerc doesn't exist
    coveragerc = project_root / ".coveragerc"
    if not coveragerc.exists():
        cmd_with_cov = [arg for arg in cmd_with_cov if not arg.startswith("--cov-config")]

    result = subprocess.run(cmd_with_cov, cwd=project_root, capture_output=True, text=True)

    if result.returncode == 0:
        print("✅ Coverage completed successfully")
        return True
    else:
        print("❌ Coverage failed:")
        print(f"   Return code: {result.returncode}")
        if "no such table: tracer" in result.stderr:
            print("   Issue: Coverage database corruption detected")
        print(f"   stderr: {result.stderr[-500:]}")  # Last 500 chars
        return False


def create_coverage_config(project_root: Path):
    """Create a basic .coveragerc file to avoid issues."""
    coveragerc = project_root / ".coveragerc"

    if coveragerc.exists():
        print("✅ .coveragerc already exists")
        return

    print("📝 Creating .coveragerc configuration...")

    config_content = """[run]
source = plugins
omit =
    */tests/*
    */test_*
    */conftest.py
    */venv/*
    */__pycache__/*

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise AssertionError
    raise NotImplementedError
    if __name__ == .__main__.:
    if TYPE_CHECKING:

[html]
directory = htmlcov
"""

    with open(coveragerc, 'w') as f:
        f.write(config_content)

    print(f"✅ Created {coveragerc}")


def main():
    """Main function to fix coverage issues."""
    print("🔧 Coverage Issue Diagnostic and Fix Tool")
    print("=" * 45)

    project_root = Path(__file__).parent.parent

    # Step 1: Clean existing coverage files
    clean_coverage_files(project_root)

    # Step 2: Check installation
    if not check_coverage_installation():
        print("\n❌ Please install coverage tools:")
        print("   pip install coverage>=7.3.0 pytest-cov")
        return 1

    # Step 3: Check configuration
    fix_pytest_configuration(project_root)

    # Step 4: Create coverage config if needed
    create_coverage_config(project_root)

    # Step 5: Test basic functionality
    if test_coverage_functionality(project_root):
        print("\n✅ Coverage is working correctly!")
    else:
        print("\n❌ Coverage still has issues")

    # Step 6: Try running component tests with coverage
    print("\n" + "=" * 45)
    if run_coverage_without_issues(project_root):
        print("\n🎉 Component tests with coverage completed successfully!")
        print("\nTo run again:")
        print("   pytest tests/component/ --cov=plugins.action --cov=plugins.module_utils --cov-report=html")
    else:
        print("\n❌ Coverage issues persist")
        provide_solutions()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
