#!/usr/bin/env python3
"""
Comprehensive Test Suite Validation and Performance Benchmarking

This script runs a complete validation of the test suite including:
- Test execution validation
- Performance benchmarking
- Coverage measurement
- Quality gate enforcement
- Contract compliance verification
"""

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class ValidationResults:
    """Results of comprehensive validation."""

    quality_gates: bool = False
    performance: bool = False
    coverage: bool = False
    unit_tests: bool = False
    component_tests: bool = False
    execution_time: float = 0.0
    coverage_percentage: float = 0.0
    test_counts: Dict[str, int] = field(default_factory=dict)
    violations: List[str] = field(default_factory=list)
    benchmarks: Dict[str, float] = field(default_factory=dict)

    @property
    def overall_success(self) -> bool:
        """Check if all validations passed."""
        return all(
            [
                self.quality_gates,
                self.performance,
                self.coverage,
                self.unit_tests,
                self.component_tests,
            ]
        )


class ComprehensiveValidator:
    """Comprehensive test suite validator and benchmarker."""

    def __init__(self, project_root: Path):
        """Initialize validator."""
        self.project_root = project_root
        self.results = ValidationResults()

    def run_quality_gates(self) -> Tuple[bool, float, List[str]]:
        """Run quality gates validation."""
        print("🔍 Running Quality Gates Validation...")
        start_time = time.time()

        cmd = [sys.executable, "scripts/test_quality_gates.py"]
        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)

        execution_time = time.time() - start_time
        violations = []

        if result.returncode != 0:
            # Parse violations from output
            lines = result.stdout.split("\n")
            for line in lines:
                if "violations" in line.lower() or "failed" in line.lower():
                    violations.append(line.strip())

        success = result.returncode == 0
        print(
            f"   {'✅ PASSED' if success else '❌ FAILED'} - Quality Gates ({execution_time:.2f}s)"
        )

        return success, execution_time, violations

    def run_performance_validation(self) -> Tuple[bool, float, Dict[str, float]]:
        """Run performance validation and benchmarking."""
        print("⚡ Running Performance Validation...")
        start_time = time.time()

        cmd = [sys.executable, "scripts/performance_validation.py"]
        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)

        execution_time = time.time() - start_time
        benchmarks = {}

        # Parse performance results
        lines = result.stdout.split("\n")
        for line in lines:
            if "Total time:" in line:
                try:
                    time_str = line.split(":")[1].strip().replace("s", "")
                    benchmarks["unit_tests"] = float(time_str)
                except (IndexError, ValueError):
                    pass
            elif "Component tests:" in line and "Total time:" in line:
                try:
                    time_str = line.split(":")[2].strip().replace("s", "")
                    benchmarks["component_tests"] = float(time_str)
                except (IndexError, ValueError):
                    pass

        success = result.returncode == 0
        print(
            f"   {'✅ PASSED' if success else '❌ FAILED'} - Performance Validation ({execution_time:.2f}s)"
        )

        return success, execution_time, benchmarks

    def run_coverage_automation(self) -> Tuple[bool, float, float]:
        """Run coverage measurement automation."""
        print("📊 Running Coverage Automation...")
        start_time = time.time()

        cmd = [sys.executable, "scripts/coverage_automation.py"]
        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)

        execution_time = time.time() - start_time
        coverage_percentage = 0.0

        # Parse coverage percentage from output
        lines = result.stdout.split("\n")
        for line in lines:
            if "Overall Coverage:" in line:
                try:
                    percentage_str = line.split(":")[1].strip().replace("%", "")
                    coverage_percentage = float(percentage_str)
                except (IndexError, ValueError):
                    pass

        success = result.returncode == 0
        print(
            f"   {'✅ PASSED' if success else '❌ FAILED'} - Coverage Automation ({execution_time:.2f}s)"
        )

        return success, execution_time, coverage_percentage

    def run_unit_tests_benchmark(self) -> Tuple[bool, float, Dict[str, int]]:
        """Run unit tests with detailed benchmarking."""
        print("🧪 Running Unit Tests Benchmark...")
        start_time = time.time()

        cmd = [sys.executable, "-m", "pytest", "tests/unit/", "-v", "--tb=short", "--durations=10"]

        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
        execution_time = time.time() - start_time

        # Parse test counts
        test_counts = {"passed": 0, "failed": 0, "skipped": 0}
        lines = result.stdout.split("\n")

        for line in lines:
            if "passed" in line and "failed" not in line:
                try:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "passed":
                            test_counts["passed"] = int(parts[i - 1])
                except (IndexError, ValueError):
                    pass
            elif "failed" in line and "passed" in line:
                try:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "failed,":
                            test_counts["failed"] = int(parts[i - 1])
                        elif part == "passed":
                            test_counts["passed"] = int(parts[i - 1])
                except (IndexError, ValueError):
                    pass

        success = result.returncode == 0
        print(f"   {'✅ PASSED' if success else '❌ FAILED'} - Unit Tests ({execution_time:.2f}s)")

        return success, execution_time, test_counts

    def run_component_tests_benchmark(self) -> Tuple[bool, float, Dict[str, int]]:
        """Run component tests with detailed benchmarking."""
        print("🔧 Running Component Tests Benchmark...")
        start_time = time.time()

        cmd = [
            sys.executable,
            "-m",
            "pytest",
            "tests/component/",
            "-v",
            "--tb=short",
            "--durations=10",
        ]

        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
        execution_time = time.time() - start_time

        # Parse test counts
        test_counts = {"passed": 0, "failed": 0, "skipped": 0}
        lines = result.stdout.split("\n")

        for line in lines:
            if "passed" in line and "failed" not in line:
                try:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "passed":
                            test_counts["passed"] = int(parts[i - 1])
                except (IndexError, ValueError):
                    pass

        success = result.returncode == 0
        print(
            f"   {'✅ PASSED' if success else '❌ FAILED'} - Component Tests ({execution_time:.2f}s)"
        )

        return success, execution_time, test_counts

    def run_parallel_benchmark(self) -> Tuple[bool, float]:
        """Run parallel execution benchmark."""
        print("🚀 Running Parallel Execution Benchmark...")
        start_time = time.time()

        cmd = [sys.executable, "-m", "pytest", "-n", "auto", "--tb=short", "-q"]

        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
        execution_time = time.time() - start_time

        success = result.returncode == 0
        print(
            f"   {'✅ PASSED' if success else '❌ FAILED'} - Parallel Tests ({execution_time:.2f}s)"
        )

        return success, execution_time

    def generate_benchmark_report(self) -> str:
        """Generate comprehensive benchmark report."""
        report = [
            "Comprehensive Test Suite Validation Report",
            "=" * 50,
            "",
            f"Overall Status: {'✅ ALL PASSED' if self.results.overall_success else '❌ SOME FAILED'}",
            f"Total Execution Time: {self.results.execution_time:.2f}s",
            f"Coverage Percentage: {self.results.coverage_percentage:.1f}%",
            "",
            "Individual Component Results:",
            "-" * 32,
            f"Quality Gates: {'✅' if self.results.quality_gates else '❌'}",
            f"Performance Validation: {'✅' if self.results.performance else '❌'}",
            f"Coverage Automation: {'✅' if self.results.coverage else '❌'}",
            f"Unit Tests: {'✅' if self.results.unit_tests else '❌'}",
            f"Component Tests: {'✅' if self.results.component_tests else '❌'}",
            "",
        ]

        # Test counts summary
        if self.results.test_counts:
            unit_counts = self.results.test_counts.get("unit", {})
            component_counts = self.results.test_counts.get("component", {})

            report.extend(
                [
                    "Test Execution Summary:",
                    "-" * 24,
                    f"Unit Tests: {unit_counts.get('passed', 0)} passed, {unit_counts.get('failed', 0)} failed",
                    f"Component Tests: {component_counts.get('passed', 0)} passed, {component_counts.get('failed', 0)} failed",
                    "",
                ]
            )

        # Performance benchmarks
        if self.results.benchmarks:
            report.extend(["Performance Benchmarks:", "-" * 24])

            for benchmark_name, time_value in self.results.benchmarks.items():
                status = "✅" if time_value <= 15.0 else "⚠️"  # 15s threshold
                report.append(f"{status} {benchmark_name}: {time_value:.2f}s")

            report.append("")

        # Violations summary
        if self.results.violations:
            report.extend(["Quality Violations:", "-" * 19])

            for violation in self.results.violations[:10]:  # Show first 10
                report.append(f"❌ {violation}")

            if len(self.results.violations) > 10:
                report.append(f"... and {len(self.results.violations) - 10} more violations")

            report.append("")

        # Performance analysis
        total_time = self.results.execution_time
        benchmark_time = sum(self.results.benchmarks.values())

        if total_time > 0:
            overhead = ((total_time - benchmark_time) / total_time) * 100
            report.extend(
                [
                    "Performance Analysis:",
                    "-" * 21,
                    f"Total execution time: {total_time:.2f}s",
                    f"Test execution time: {benchmark_time:.2f}s",
                    f"Overhead: {overhead:.1f}%",
                    "",
                ]
            )

        # Recommendations
        report.extend(["Recommendations:", "-" * 16])

        if self.results.overall_success:
            report.extend(
                [
                    "✅ All validations passed successfully!",
                    "✅ Test suite meets all quality standards",
                    "✅ Performance requirements satisfied",
                    "✅ Coverage targets achieved",
                    "",
                ]
            )
        else:
            if not self.results.quality_gates:
                report.append("❌ Fix quality gate violations before proceeding")
            if not self.results.performance:
                report.append("❌ Address performance issues in slow tests")
            if not self.results.coverage:
                report.append("❌ Improve test coverage to meet targets")
            if not self.results.unit_tests:
                report.append("❌ Fix failing unit tests")
            if not self.results.component_tests:
                report.append("❌ Fix failing component tests")
            report.append("")

        # Quality metrics
        if self.results.coverage_percentage > 0:
            coverage_status = "✅" if self.results.coverage_percentage >= 80 else "❌"
            report.extend(
                [
                    "Quality Metrics:",
                    "-" * 16,
                    f"{coverage_status} Coverage: {self.results.coverage_percentage:.1f}% (target: ≥80%)",
                ]
            )

        return "\n".join(report)

    def save_results(self) -> None:
        """Save validation results to JSON file."""
        results_data = {
            "timestamp": time.time(),
            "overall_success": self.results.overall_success,
            "quality_gates": self.results.quality_gates,
            "performance": self.results.performance,
            "coverage": self.results.coverage,
            "unit_tests": self.results.unit_tests,
            "component_tests": self.results.component_tests,
            "execution_time": self.results.execution_time,
            "coverage_percentage": self.results.coverage_percentage,
            "test_counts": self.results.test_counts,
            "violations": self.results.violations,
            "benchmarks": self.results.benchmarks,
        }

        results_file = self.project_root / "comprehensive_validation_results.json"
        with open(results_file, "w") as f:
            json.dump(results_data, f, indent=2)

        print(f"Results saved to: {results_file}")

    def run_comprehensive_validation(self) -> bool:
        """Run complete comprehensive validation."""
        print("🚀 Starting Comprehensive Test Suite Validation")
        print("=" * 55)

        total_start_time = time.time()

        # Run quality gates
        quality_success, quality_time, violations = self.run_quality_gates()
        self.results.quality_gates = quality_success
        self.results.violations = violations

        # Run performance validation
        perf_success, perf_time, benchmarks = self.run_performance_validation()
        self.results.performance = perf_success
        self.results.benchmarks.update(benchmarks)

        # Run coverage automation
        cov_success, cov_time, coverage_pct = self.run_coverage_automation()
        self.results.coverage = cov_success
        self.results.coverage_percentage = coverage_pct

        # Run unit tests benchmark
        unit_success, unit_time, unit_counts = self.run_unit_tests_benchmark()
        self.results.unit_tests = unit_success
        self.results.test_counts["unit"] = unit_counts
        self.results.benchmarks["unit_tests_direct"] = unit_time

        # Run component tests benchmark
        comp_success, comp_time, comp_counts = self.run_component_tests_benchmark()
        self.results.component_tests = comp_success
        self.results.test_counts["component"] = comp_counts
        self.results.benchmarks["component_tests_direct"] = comp_time

        # Run parallel benchmark (optional)
        try:
            parallel_success, parallel_time = self.run_parallel_benchmark()
            self.results.benchmarks["parallel_execution"] = parallel_time
        except Exception as e:
            print(f"⚠️  Parallel benchmark failed: {e}")

        # Calculate total time
        self.results.execution_time = time.time() - total_start_time

        # Generate and display report
        print("\n" + "=" * 55)
        report = self.generate_benchmark_report()
        print(report)

        # Save results
        self.save_results()

        return self.results.overall_success


def main():
    """Main entry point for comprehensive validation."""
    project_root = Path(__file__).parent.parent
    validator = ComprehensiveValidator(project_root)

    success = validator.run_comprehensive_validation()

    if success:
        print("\n🎉 Comprehensive validation completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Comprehensive validation failed. Check the report above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
