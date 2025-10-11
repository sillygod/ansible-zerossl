#!/usr/bin/env python3
"""
Cleanup Deprecated Test Patterns

This script identifies and documents deprecated test patterns that should be
avoided in the ZeroSSL plugin test suite. It serves as a maintenance tool
to ensure test quality standards are maintained.
"""

import ast
import re
from pathlib import Path
from typing import List, Dict, Tuple


class DeprecatedPatternDetector:
    """Detects deprecated testing patterns that should be cleaned up."""

    # Patterns that indicate deprecated test approaches
    DEPRECATED_PATTERNS = {
        "internal_method_mocking": [
            r"_handle_present_state.*=.*Mock",
            r"_create_certificate.*=.*Mock",
            r"_validate_certificate.*=.*Mock",
            r"_download_certificate.*=.*Mock",
            r"get_certificate_status.*=.*Mock",
        ],
        "excessive_mock_objects": [
            r"Mock\(\).*Mock\(\)",  # Multiple Mock() in same line
            r"Mock.*return_value.*Mock",  # Nested Mock patterns
        ],
        "non_boundary_mocking": [
            r"mocker\.patch.*certificate_manager\.",
            r"mocker\.patch.*api_client\.",
            r"mocker\.patch.*validation_handler\.",
        ],
        "hardcoded_responses": [
            r'return_value\s*=\s*{.*"id".*}',  # Hardcoded dict responses
        ],
    }

    # Files that are allowed to have special patterns (contract tests, etc.)
    ALLOWED_EXCEPTIONS = {
        "test_execution_contract_validation.py",
        "test_coverage_measurement_validation.py",
        "test_mock_boundary_validation.py",
    }

    def __init__(self, test_directory: Path):
        """Initialize pattern detector."""
        self.test_directory = test_directory
        self.violations = []

    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan a file for deprecated patterns."""
        violations = []

        if file_path.name in self.ALLOWED_EXCEPTIONS:
            return violations

        try:
            with open(file_path, "r") as f:
                content = f.read()

            lines = content.split("\n")

            for pattern_category, patterns in self.DEPRECATED_PATTERNS.items():
                for pattern in patterns:
                    for line_num, line in enumerate(lines, 1):
                        if re.search(pattern, line):
                            violations.append(
                                {
                                    "file": str(file_path),
                                    "line": line_num,
                                    "category": pattern_category,
                                    "pattern": pattern,
                                    "content": line.strip(),
                                    "severity": self._get_severity(pattern_category),
                                }
                            )

        except Exception as e:
            print(f"Error scanning {file_path}: {e}")

        return violations

    def _get_severity(self, category: str) -> str:
        """Get severity level for pattern category."""
        severity_map = {
            "internal_method_mocking": "HIGH",
            "excessive_mock_objects": "MEDIUM",
            "non_boundary_mocking": "HIGH",
            "hardcoded_responses": "LOW",
        }
        return severity_map.get(category, "MEDIUM")

    def scan_all_tests(self) -> Dict:
        """Scan all test files for deprecated patterns."""
        results = {"violations": [], "clean_files": [], "summary": {}}

        for test_file in self.test_directory.rglob("test_*.py"):
            violations = self.scan_file(test_file)

            if violations:
                results["violations"].extend(violations)
            else:
                results["clean_files"].append(str(test_file))

        # Generate summary
        by_category = {}
        by_severity = {}

        for violation in results["violations"]:
            category = violation["category"]
            severity = violation["severity"]

            by_category.setdefault(category, 0)
            by_category[category] += 1

            by_severity.setdefault(severity, 0)
            by_severity[severity] += 1

        results["summary"] = {
            "total_violations": len(results["violations"]),
            "by_category": by_category,
            "by_severity": by_severity,
            "clean_files_count": len(results["clean_files"]),
        }

        return results

    def generate_cleanup_report(self, results: Dict) -> str:
        """Generate cleanup report."""
        report = [
            "Deprecated Test Pattern Cleanup Report",
            "=" * 45,
            "",
            f"Total Violations: {results['summary']['total_violations']}",
            f"Clean Files: {results['summary']['clean_files_count']}",
            "",
        ]

        if results["summary"]["total_violations"] == 0:
            report.extend(
                [
                    "🎉 NO DEPRECATED PATTERNS FOUND!",
                    "",
                    "All test files follow the current testing standards:",
                    "✅ HTTP boundary mocking only",
                    "✅ Real business logic testing",
                    "✅ No internal method mocking",
                    "✅ Contract-compliant patterns",
                    "",
                ]
            )
        else:
            # Violations by severity
            report.extend(["Violations by Severity:", "-" * 25])

            for severity in ["HIGH", "MEDIUM", "LOW"]:
                count = results["summary"]["by_severity"].get(severity, 0)
                if count > 0:
                    report.append(f"{severity}: {count} violations")

            report.append("")

            # Violations by category
            report.extend(["Violations by Category:", "-" * 25])

            for category, count in results["summary"]["by_category"].items():
                report.append(f"{category}: {count} violations")

            report.append("")

            # Detailed violations
            report.extend(["Detailed Violations:", "-" * 20])

            high_priority = [v for v in results["violations"] if v["severity"] == "HIGH"]
            medium_priority = [v for v in results["violations"] if v["severity"] == "MEDIUM"]
            low_priority = [v for v in results["violations"] if v["severity"] == "LOW"]

            for priority_group, label in [
                (high_priority, "HIGH PRIORITY"),
                (medium_priority, "MEDIUM PRIORITY"),
                (low_priority, "LOW PRIORITY"),
            ]:
                if priority_group:
                    report.append(f"\n{label}:")
                    for violation in priority_group[:10]:  # Show first 10
                        file_short = Path(violation["file"]).name
                        report.append(
                            f"  {file_short}:{violation['line']} - {violation['category']}"
                        )
                        report.append(f"    Pattern: {violation['pattern']}")
                        report.append(f"    Code: {violation['content']}")
                        report.append("")

        # Clean files summary
        if results["clean_files"]:
            report.extend(["Clean Files (Following Current Standards):", "-" * 42])
            for clean_file in results["clean_files"][:20]:  # Show first 20
                file_short = Path(clean_file).name
                report.append(f"✅ {file_short}")

            if len(results["clean_files"]) > 20:
                report.append(f"... and {len(results['clean_files']) - 20} more clean files")

        return "\n".join(report)

    def suggest_fixes(self, violations: List[Dict]) -> str:
        """Suggest fixes for common violations."""
        fixes = ["", "Suggested Fixes:", "=" * 16, ""]

        fix_suggestions = {
            "internal_method_mocking": [
                "❌ WRONG: manager._create_certificate = Mock()",
                "✅ CORRECT: mock_http_boundary('/certificates', response_data)",
                "",
            ],
            "excessive_mock_objects": [
                "❌ WRONG: Mock().method.return_value = Mock()",
                "✅ CORRECT: Use real objects with HTTP boundary mocking",
                "",
            ],
            "non_boundary_mocking": [
                "❌ WRONG: mocker.patch('module.BusinessClass.method')",
                "✅ CORRECT: Use real business classes with HTTP boundary mocking",
                "",
            ],
            "hardcoded_responses": [
                "❌ WRONG: return_value = {'id': 'test123'}",
                "✅ CORRECT: Use fixture data from tests/fixtures/",
                "",
            ],
        }

        categories_found = set(v["category"] for v in violations)

        for category in categories_found:
            if category in fix_suggestions:
                fixes.extend(fix_suggestions[category])

        return "\n".join(fixes)


def main():
    """Main entry point for cleanup script."""
    project_root = Path(__file__).parent.parent
    test_directory = project_root / "tests"

    detector = DeprecatedPatternDetector(test_directory)
    results = detector.scan_all_tests()

    # Generate and display report
    report = detector.generate_cleanup_report(results)
    print(report)

    # Show fix suggestions if violations found
    if results["violations"]:
        fixes = detector.suggest_fixes(results["violations"])
        print(fixes)

    # Save results
    results_file = project_root / "deprecated_patterns_report.json"
    import json

    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nDetailed results saved to: {results_file}")

    # Return appropriate exit code
    return 0 if results["summary"]["total_violations"] == 0 else 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
