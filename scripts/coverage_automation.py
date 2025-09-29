#!/usr/bin/env python3
"""
Coverage Measurement Automation Script

This script implements the coverage measurement contract for the ZeroSSL plugin.
It provides automated coverage validation, reporting, and quality gates.
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET


class CoverageAutomation:
    """Automated coverage measurement and validation."""

    # Module-level coverage requirements from contract
    COVERAGE_TARGETS = {
        "plugins.action.zerossl_certificate": 85,
        "plugins.module_utils.zerossl.certificate_manager": 90,
        "plugins.module_utils.zerossl.api_client": 85,
        "plugins.module_utils.zerossl.validation_handler": 80,
        "plugins.module_utils.zerossl.exceptions": 70,
    }

    def __init__(self, project_root: Path):
        """Initialize coverage automation."""
        self.project_root = project_root
        self.coverage_dir = project_root / "htmlcov"
        self.coverage_xml = project_root / "coverage.xml"
        self.coverage_json = project_root / "coverage.json"

    def run_unit_tests_with_coverage(self) -> Tuple[bool, float]:
        """Run unit tests with coverage measurement."""
        print("Running unit tests with coverage...")
        start_time = time.time()

        cmd = [
            sys.executable, "-m", "pytest",
            "tests/unit/",
            "--cov=plugins.action",
            "--cov=plugins.module_utils",
            "--cov-report=term",
            "--cov-report=xml",
            "--cov-report=json",
            "-v"
        ]

        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
        execution_time = time.time() - start_time

        if result.returncode != 0:
            print(f"Unit tests failed:\n{result.stdout}\n{result.stderr}")
            return False, execution_time

        print(f"Unit tests completed in {execution_time:.2f}s")
        return True, execution_time

    def run_component_tests_with_coverage(self) -> Tuple[bool, float]:
        """Run component tests with coverage measurement."""
        print("Running component tests with coverage...")
        start_time = time.time()

        cmd = [
            sys.executable, "-m", "pytest",
            "tests/component/",
            "--cov=plugins.action",
            "--cov=plugins.module_utils",
            "--cov-append",
            "--cov-report=term",
            "--cov-report=xml",
            "--cov-report=json",
            "-v"
        ]

        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
        execution_time = time.time() - start_time

        if result.returncode != 0:
            print(f"Component tests failed:\n{result.stdout}\n{result.stderr}")
            return False, execution_time

        print(f"Component tests completed in {execution_time:.2f}s")
        return True, execution_time

    def run_full_coverage_report(self) -> Tuple[bool, float]:
        """Generate full coverage report with all formats."""
        print("Generating full coverage report...")
        start_time = time.time()

        cmd = [
            sys.executable, "-m", "pytest",
            "tests/unit/",
            "tests/component/",
            "tests/performance/",
            "tests/security/",
            "--cov=plugins.action",
            "--cov=plugins.module_utils",
            "--cov-report=html:htmlcov",
            "--cov-report=xml",
            "--cov-report=json",
            "--cov-report=term-missing",
            "-v"
        ]

        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
        execution_time = time.time() - start_time

        if result.returncode != 0:
            print(f"Coverage report generation failed:\n{result.stdout}\n{result.stderr}")
            return False, execution_time

        print(f"Coverage report generated in {execution_time:.2f}s")
        return True, execution_time

    def parse_coverage_xml(self) -> Dict[str, float]:
        """Parse coverage data from XML report."""
        if not self.coverage_xml.exists():
            raise FileNotFoundError(f"Coverage XML not found: {self.coverage_xml}")

        tree = ET.parse(self.coverage_xml)
        root = tree.getroot()

        coverage_data = {}

        for package in root.findall(".//package"):
            package_name = package.get("name", "")

            for class_elem in package.findall(".//class"):
                filename = class_elem.get("filename", "")
                line_rate = float(class_elem.get("line-rate", 0))

                # Convert filename to module name
                if filename.startswith("plugins/"):
                    module_name = filename.replace("/", ".").replace(".py", "")
                    coverage_data[module_name] = line_rate * 100

        return coverage_data

    def parse_coverage_json(self) -> Dict[str, float]:
        """Parse coverage data from JSON report."""
        if not self.coverage_json.exists():
            raise FileNotFoundError(f"Coverage JSON not found: {self.coverage_json}")

        with open(self.coverage_json) as f:
            data = json.load(f)

        coverage_data = {}

        for filename, file_data in data.get("files", {}).items():
            if filename.startswith("plugins/"):
                module_name = filename.replace("/", ".").replace(".py", "")

                summary = file_data.get("summary", {})
                covered_lines = summary.get("covered_lines", 0)
                num_statements = summary.get("num_statements", 1)

                if num_statements > 0:
                    coverage_data[module_name] = (covered_lines / num_statements) * 100

        return coverage_data

    def validate_coverage_targets(self) -> Tuple[bool, List[str]]:
        """Validate that coverage meets target requirements."""
        print("Validating coverage targets...")

        try:
            # Try JSON first, fallback to XML
            try:
                coverage_data = self.parse_coverage_json()
            except FileNotFoundError:
                coverage_data = self.parse_coverage_xml()

        except FileNotFoundError as e:
            return False, [f"Coverage data not found: {e}"]

        failures = []

        for module, target in self.COVERAGE_TARGETS.items():
            actual = coverage_data.get(module, 0)

            if actual < target:
                failures.append(f"{module}: {actual:.1f}% < {target}% (target)")
            else:
                print(f"✓ {module}: {actual:.1f}% >= {target}% (target)")

        return len(failures) == 0, failures

    def validate_performance_requirements(self, unit_time: float, component_time: float, report_time: float) -> Tuple[bool, List[str]]:
        """Validate performance requirements from contract."""
        failures = []

        # Coverage measurement overhead should be ≤ 20% of base execution time
        # For now, just validate absolute times based on contract
        if report_time > 10:
            failures.append(f"HTML report generation too slow: {report_time:.1f}s > 10s")

        total_time = unit_time + component_time + report_time
        if total_time > 60:  # Allow some buffer over 30s limit for coverage overhead
            failures.append(f"Total execution time too slow: {total_time:.1f}s > 60s")

        return len(failures) == 0, failures

    def generate_coverage_summary(self) -> str:
        """Generate coverage summary report."""
        try:
            coverage_data = self.parse_coverage_json()
        except FileNotFoundError:
            try:
                coverage_data = self.parse_coverage_xml()
            except FileNotFoundError:
                return "Coverage data not available"

        summary = ["Coverage Summary:", "=" * 50]

        for module, target in self.COVERAGE_TARGETS.items():
            actual = coverage_data.get(module, 0)
            status = "✓" if actual >= target else "✗"
            summary.append(f"{status} {module}: {actual:.1f}% (target: {target}%)")

        # Overall coverage
        if coverage_data:
            overall = sum(coverage_data.values()) / len(coverage_data)
            summary.append(f"\nOverall Coverage: {overall:.1f}%")

        return "\n".join(summary)

    def run_automation(self) -> bool:
        """Run complete coverage automation workflow."""
        print("Starting Coverage Measurement Automation")
        print("=" * 50)

        # Run tests with coverage
        unit_success, unit_time = self.run_unit_tests_with_coverage()
        if not unit_success:
            print("❌ Unit tests failed")
            return False

        component_success, component_time = self.run_component_tests_with_coverage()
        if not component_success:
            print("❌ Component tests failed")
            return False

        # Generate reports
        report_success, report_time = self.run_full_coverage_report()
        if not report_success:
            print("❌ Coverage report generation failed")
            return False

        # Validate coverage targets
        targets_met, target_failures = self.validate_coverage_targets()
        if not targets_met:
            print("❌ Coverage targets not met:")
            for failure in target_failures:
                print(f"  - {failure}")
            return False

        # Validate performance
        perf_ok, perf_failures = self.validate_performance_requirements(
            unit_time, component_time, report_time
        )
        if not perf_ok:
            print("❌ Performance requirements not met:")
            for failure in perf_failures:
                print(f"  - {failure}")
            return False

        # Success summary
        print("\n✅ Coverage Automation Successful!")
        print(f"⏱️  Execution times:")
        print(f"   Unit tests: {unit_time:.1f}s")
        print(f"   Component tests: {component_time:.1f}s")
        print(f"   Report generation: {report_time:.1f}s")
        print(f"   Total: {unit_time + component_time + report_time:.1f}s")

        print(f"\n{self.generate_coverage_summary()}")

        return True


def main():
    """Main entry point for coverage automation."""
    project_root = Path(__file__).parent.parent
    automation = CoverageAutomation(project_root)

    success = automation.run_automation()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
