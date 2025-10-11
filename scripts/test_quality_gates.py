#!/usr/bin/env python3
"""
Test Quality Gates

This script implements quality gates to prevent regression in test design,
specifically over-mocking and ensure adherence to HTTP boundary mocking principles.
"""

import ast
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
import importlib.util


@dataclass
class MockingViolation:
    """Represents a mocking boundary violation."""

    file_path: str
    line_number: int
    violation_type: str
    description: str
    code_snippet: str


@dataclass
class QualityGateResults:
    """Results of quality gate analysis."""

    violations: List[MockingViolation] = field(default_factory=list)
    allowed_boundaries: Set[str] = field(default_factory=set)
    forbidden_mocks: Set[str] = field(default_factory=set)
    test_method_coverage: Dict[str, int] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """Check if all quality gates passed."""
        return len(self.violations) == 0


class TestQualityAnalyzer:
    """Analyzes test files for quality gate compliance."""

    # Allowed mock boundaries (from contract)
    ALLOWED_MOCK_BOUNDARIES = {
        "requests.Session",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "pathlib.Path.open",
        "pathlib.Path.write_text",
        "pathlib.Path.read_text",
        "pathlib.Path.exists",
        "pathlib.Path.mkdir",
        "os.path.exists",
        "os.makedirs",
        "builtins.open",
        "dns.resolver.Resolver",
        "socket.create_connection",
        "ssl.create_default_context",
    }

    # Forbidden internal mocking patterns
    FORBIDDEN_MOCK_PATTERNS = {
        "_handle_present_state",
        "_create_certificate",
        "_validate_certificate",
        "_download_certificate",
        "_check_certificate_status",
        "get_certificate_status",
        "create_certificate",
        "validate_certificate",
        "list_certificates",
        "needs_renewal",
        "prepare_http_validation",
        "verify_http_validation",
        "place_validation_files",
    }

    def __init__(self, project_root: Path):
        """Initialize quality analyzer."""
        self.project_root = project_root
        self.test_dirs = [project_root / "tests" / "unit", project_root / "tests" / "component"]

    def analyze_file(self, file_path: Path) -> List[MockingViolation]:
        """Analyze a single test file for quality gate violations."""
        violations = []

        try:
            with open(file_path, "r") as f:
                content = f.read()

            # Parse AST for detailed analysis
            tree = ast.parse(content)
            violations.extend(self._analyze_ast(file_path, tree, content))

            # Text-based pattern analysis for additional checks
            violations.extend(self._analyze_text_patterns(file_path, content))

        except Exception as e:
            violations.append(
                MockingViolation(
                    file_path=str(file_path),
                    line_number=1,
                    violation_type="parse_error",
                    description=f"Failed to parse file: {e}",
                    code_snippet="",
                )
            )

        return violations

    def _analyze_ast(self, file_path: Path, tree: ast.AST, content: str) -> List[MockingViolation]:
        """Analyze AST for mocking violations."""
        violations = []
        lines = content.split("\n")

        class MockVisitor(ast.NodeVisitor):
            def visit_Call(self, node):
                # Check for mock.patch calls
                if isinstance(node.func, ast.Attribute):
                    if (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "mock"
                        and node.func.attr == "patch"
                    ):

                        if node.args and isinstance(node.args[0], ast.Constant):
                            patch_target = node.args[0].value
                            if not self._is_allowed_mock_target(patch_target):
                                violations.append(
                                    MockingViolation(
                                        file_path=str(file_path),
                                        line_number=node.lineno,
                                        violation_type="forbidden_mock",
                                        description=f"Forbidden mock target: {patch_target}",
                                        code_snippet=(
                                            lines[node.lineno - 1]
                                            if node.lineno <= len(lines)
                                            else ""
                                        ),
                                    )
                                )

                # Check for mocker.patch calls
                elif (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "mocker"
                    and node.func.attr == "patch"
                ):

                    if node.args and isinstance(node.args[0], ast.Constant):
                        patch_target = node.args[0].value
                        if not self._is_allowed_mock_target(patch_target):
                            violations.append(
                                MockingViolation(
                                    file_path=str(file_path),
                                    line_number=node.lineno,
                                    violation_type="forbidden_mock",
                                    description=f"Forbidden mocker.patch target: {patch_target}",
                                    code_snippet=(
                                        lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                                    ),
                                )
                            )

                self.generic_visit(node)

            def _is_allowed_mock_target(self, target: str) -> bool:
                """Check if mock target is allowed."""
                # Allow explicit HTTP boundary mocks
                for allowed in TestQualityAnalyzer.ALLOWED_MOCK_BOUNDARIES:
                    if allowed in target:
                        return True

                # Forbid internal business logic mocks
                for forbidden in TestQualityAnalyzer.FORBIDDEN_MOCK_PATTERNS:
                    if forbidden in target:
                        return False

                # Allow certain standard library mocks
                stdlib_allowed = [
                    "builtins.",
                    "os.",
                    "sys.",
                    "time.",
                    "datetime.",
                    "json.",
                    "pathlib.",
                    "tempfile.",
                ]

                for allowed_prefix in stdlib_allowed:
                    if target.startswith(allowed_prefix):
                        return True

                # Deny by default for safety
                return False

        visitor = MockVisitor()
        visitor.visit(tree)
        return violations

    def _analyze_text_patterns(self, file_path: Path, content: str) -> List[MockingViolation]:
        """Analyze text patterns for additional violations."""
        violations = []
        lines = content.split("\n")

        # Pattern for excessive Mock object usage
        mock_object_pattern = re.compile(r"Mock\(\)")
        for line_num, line in enumerate(lines, 1):
            if mock_object_pattern.search(line):
                # Check if this is in a test context that might be problematic
                if (
                    "return_value" in line or "side_effect" in line
                ) and "mock_http_boundary" not in line:
                    violations.append(
                        MockingViolation(
                            file_path=str(file_path),
                            line_number=line_num,
                            violation_type="excessive_mocking",
                            description="Potential over-mocking with Mock objects",
                            code_snippet=line.strip(),
                        )
                    )

        # Pattern for internal method mocking
        for pattern in self.FORBIDDEN_MOCK_PATTERNS:
            regex = re.compile(rf"\.{re.escape(pattern)}\s*=")
            for line_num, line in enumerate(lines, 1):
                if regex.search(line):
                    violations.append(
                        MockingViolation(
                            file_path=str(file_path),
                            line_number=line_num,
                            violation_type="internal_method_mock",
                            description=f"Forbidden internal method mock: {pattern}",
                            code_snippet=line.strip(),
                        )
                    )

        return violations

    def analyze_test_method_coverage(self, file_path: Path) -> Dict[str, int]:
        """Analyze test method coverage for source modules."""
        coverage = {}

        try:
            with open(file_path, "r") as f:
                content = f.read()

            # Count test methods
            test_method_pattern = re.compile(r"def test_\w+")
            test_methods = test_method_pattern.findall(content)

            # Determine which module this test file covers
            file_name = file_path.name
            if "api_client" in file_name:
                coverage["ZeroSSLAPIClient"] = len(test_methods)
            elif "certificate_manager" in file_name:
                coverage["CertificateManager"] = len(test_methods)
            elif "validation_handler" in file_name:
                coverage["ValidationHandler"] = len(test_methods)
            elif "action" in file_name or "plugin" in file_name:
                coverage["ActionModule"] = len(test_methods)

        except Exception:
            pass

        return coverage

    def check_real_code_paths(self, file_path: Path) -> bool:
        """Check if tests exercise real code paths."""
        try:
            # Contract validation tests are exempt from real code path requirements
            # They validate the contracts themselves, not business logic
            contract_test_files = {
                "test_execution_contract_validation.py",
                "test_coverage_measurement_validation.py",
                "test_mock_boundary_validation.py",
            }

            if file_path.name in contract_test_files:
                return True  # Contract tests are always considered valid

            with open(file_path, "r") as f:
                content = f.read()

            # Look for indicators of real code path testing
            real_indicators = [
                "mock_http_boundary",  # Our approved HTTP mocking
                "real_api_client",  # Real client fixtures
                "real_certificate_manager",  # Real manager fixtures
                "ActionModule(",  # Real ActionModule instantiation
                "ValidationHandler(",  # Real ValidationHandler instantiation
            ]

            # Must have at least one real indicator
            for indicator in real_indicators:
                if indicator in content:
                    return True

            return False

        except Exception:
            return False

    def run_quality_gates(self) -> QualityGateResults:
        """Run all quality gate checks."""
        results = QualityGateResults()

        print("Running Test Quality Gate Analysis...")
        print("=" * 45)

        # Analyze all test files
        for test_dir in self.test_dirs:
            if not test_dir.exists():
                continue

            for test_file in test_dir.glob("test_*.py"):
                print(f"Analyzing {test_file.relative_to(self.project_root)}...")

                # Check for mocking violations
                violations = self.analyze_file(test_file)
                results.violations.extend(violations)

                # Check test method coverage
                coverage = self.analyze_test_method_coverage(test_file)
                results.test_method_coverage.update(coverage)

                # Check for real code path usage
                has_real_paths = self.check_real_code_paths(test_file)
                if not has_real_paths:
                    results.violations.append(
                        MockingViolation(
                            file_path=str(test_file),
                            line_number=1,
                            violation_type="no_real_code_paths",
                            description="No real code path testing detected",
                            code_snippet="",
                        )
                    )

        return results

    def generate_quality_report(self, results: QualityGateResults) -> str:
        """Generate quality gate report."""
        report = [
            "Test Quality Gate Report",
            "=" * 30,
            "",
            f"Total Violations: {len(results.violations)}",
            f"Quality Gates: {'✅ PASSED' if results.passed else '❌ FAILED'}",
            "",
        ]

        if results.violations:
            report.extend(["Violations by Type:", "-" * 20])

            violation_types = {}
            for violation in results.violations:
                violation_types.setdefault(violation.violation_type, []).append(violation)

            for violation_type, violations in violation_types.items():
                report.append(f"{violation_type}: {len(violations)} violations")
                for violation in violations[:5]:  # Show first 5
                    report.append(
                        f"  {violation.file_path}:{violation.line_number} - {violation.description}"
                    )
                if len(violations) > 5:
                    report.append(f"  ... and {len(violations) - 5} more")
                report.append("")

        # Test method coverage summary
        if results.test_method_coverage:
            report.extend(["Test Method Coverage:", "-" * 22])
            for module, count in results.test_method_coverage.items():
                report.append(f"{module}: {count} test methods")
            report.append("")

        return "\n".join(report)

    def save_quality_results(self, results: QualityGateResults) -> None:
        """Save quality gate results for trend analysis."""
        output = {
            "violations": [
                {
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "type": v.violation_type,
                    "description": v.description,
                    "code_snippet": v.code_snippet,
                }
                for v in results.violations
            ],
            "test_method_coverage": results.test_method_coverage,
            "passed": results.passed,
            "summary": {
                "total_violations": len(results.violations),
                "violation_types": len(set(v.violation_type for v in results.violations)),
            },
        }

        results_file = self.project_root / "quality_gate_results.json"
        with open(results_file, "w") as f:
            json.dump(output, f, indent=2)


def main():
    """Main entry point for quality gate analysis."""
    project_root = Path(__file__).parent.parent
    analyzer = TestQualityAnalyzer(project_root)

    results = analyzer.run_quality_gates()

    # Generate and display report
    report = analyzer.generate_quality_report(results)
    print(report)

    # Save results
    analyzer.save_quality_results(results)

    sys.exit(0 if results.passed else 1)


if __name__ == "__main__":
    main()
