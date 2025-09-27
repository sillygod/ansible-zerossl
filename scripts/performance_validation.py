#!/usr/bin/env python3
"""
Performance Validation Script

This script validates that test execution meets the 30-second time limit
requirement and provides performance monitoring for the test suite.
"""

import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import statistics


@dataclass
class TestExecutionStats:
    """Statistics for test execution performance."""
    total_time: float
    test_count: int
    passed: int
    failed: int
    skipped: int
    avg_time_per_test: float
    slowest_tests: List[Tuple[str, float]]


@dataclass
class PerformanceThresholds:
    """Performance thresholds from contract."""
    max_total_time: float = 30.0  # seconds
    max_individual_test_time: float = 5.0  # seconds
    max_coverage_overhead: float = 0.2  # 20% overhead


class PerformanceValidator:
    """Validates test suite performance requirements."""

    def __init__(self, project_root: Path):
        """Initialize performance validator."""
        self.project_root = project_root
        self.thresholds = PerformanceThresholds()
        self.results_file = project_root / "performance_results.json"

    def run_unit_tests_timed(self) -> TestExecutionStats:
        """Run unit tests with detailed timing."""
        print("Running unit tests with performance monitoring...")

        start_time = time.time()

        # Run with verbose output to capture individual test times
        cmd = [
            sys.executable, "-m", "pytest",
            "tests/unit/",
            "-v",
            "--tb=short",
            "--durations=0",  # Show all test durations
            "--disable-warnings"
        ]

        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
        total_time = time.time() - start_time

        # Parse pytest output for test statistics
        stats = self._parse_pytest_output(result.stdout, total_time)

        if result.returncode != 0:
            print(f"Unit tests failed:\n{result.stderr}")
            # Still return stats for analysis

        return stats

    def run_component_tests_timed(self) -> TestExecutionStats:
        """Run component tests with detailed timing."""
        print("Running component tests with performance monitoring...")

        start_time = time.time()

        cmd = [
            sys.executable, "-m", "pytest",
            "tests/component/",
            "-v",
            "--tb=short",
            "--durations=0",
            "--disable-warnings"
        ]

        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
        total_time = time.time() - start_time

        stats = self._parse_pytest_output(result.stdout, total_time)

        if result.returncode != 0:
            print(f"Component tests failed:\n{result.stderr}")

        return stats

    def run_with_coverage_overhead_test(self) -> Tuple[float, float]:
        """Measure coverage overhead by comparing with/without coverage."""
        print("Measuring coverage overhead...")

        # Run without coverage
        start_time = time.time()
        cmd_no_cov = [
            sys.executable, "-m", "pytest",
            "tests/unit/",
            "-q",
            "--disable-warnings"
        ]
        subprocess.run(cmd_no_cov, cwd=self.project_root, capture_output=True)
        time_without_coverage = time.time() - start_time

        # Run with coverage
        start_time = time.time()
        cmd_with_cov = [
            sys.executable, "-m", "pytest",
            "tests/unit/",
            "--cov=plugins.action",
            "--cov=plugins.module_utils",
            "-q",
            "--disable-warnings"
        ]
        subprocess.run(cmd_with_cov, cwd=self.project_root, capture_output=True)
        time_with_coverage = time.time() - start_time

        return time_without_coverage, time_with_coverage

    def run_parallel_performance_test(self) -> TestExecutionStats:
        """Test parallel execution performance."""
        print("Testing parallel execution performance...")

        start_time = time.time()

        cmd = [
            sys.executable, "-m", "pytest",
            "-n", "auto",  # Use all available CPUs
            "-v",
            "--tb=short",
            "--durations=0",
            "--disable-warnings"
        ]

        result = subprocess.run(cmd, cwd=self.project_root, capture_output=True, text=True)
        total_time = time.time() - start_time

        return self._parse_pytest_output(result.stdout, total_time)

    def _parse_pytest_output(self, output: str, total_time: float) -> TestExecutionStats:
        """Parse pytest output to extract test statistics."""
        lines = output.split('\n')

        # Find test result summary line
        test_count = 0
        passed = 0
        failed = 0
        skipped = 0
        slowest_tests = []

        # Parse test results
        for line in lines:
            if "passed" in line and ("failed" in line or "error" in line):
                # Format: "X failed, Y passed in Z.ZZs"
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "failed,":
                        failed = int(parts[i-1])
                    elif part == "passed":
                        passed = int(parts[i-1])
                    elif part == "skipped,":
                        skipped = int(parts[i-1])
            elif "passed in" in line and "failed" not in line:
                # Format: "X passed in Y.YYs"
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "passed":
                        passed = int(parts[i-1])

        # Parse duration information for slowest tests
        in_duration_section = False
        for line in lines:
            if "slowest durations" in line.lower():
                in_duration_section = True
                continue
            elif in_duration_section and line.strip():
                if line.startswith("=") or "short test summary" in line.lower():
                    break
                # Format: "0.05s call tests/unit/test_api_client.py::TestZeroSSLAPIClient::test_method"
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0].endswith('s'):
                    try:
                        duration = float(parts[0][:-1])  # Remove 's' suffix
                        test_name = parts[2] if len(parts) > 2 else "unknown"
                        slowest_tests.append((test_name, duration))
                    except ValueError:
                        continue

        test_count = passed + failed + skipped
        avg_time = total_time / test_count if test_count > 0 else 0

        return TestExecutionStats(
            total_time=total_time,
            test_count=test_count,
            passed=passed,
            failed=failed,
            skipped=skipped,
            avg_time_per_test=avg_time,
            slowest_tests=slowest_tests[:10]  # Top 10 slowest
        )

    def validate_performance_thresholds(self, unit_stats: TestExecutionStats,
                                      component_stats: TestExecutionStats) -> Tuple[bool, List[str]]:
        """Validate that performance meets threshold requirements."""
        failures = []

        # Check total execution time
        total_time = unit_stats.total_time + component_stats.total_time
        if total_time > self.thresholds.max_total_time:
            failures.append(f"Total execution time {total_time:.1f}s > {self.thresholds.max_total_time}s limit")

        # Check individual test times
        all_slow_tests = unit_stats.slowest_tests + component_stats.slowest_tests
        for test_name, duration in all_slow_tests:
            if duration > self.thresholds.max_individual_test_time:
                failures.append(f"Test {test_name} took {duration:.1f}s > {self.thresholds.max_individual_test_time}s limit")

        return len(failures) == 0, failures

    def validate_coverage_overhead(self) -> Tuple[bool, List[str]]:
        """Validate coverage measurement overhead."""
        try:
            time_without, time_with = self.run_with_coverage_overhead_test()

            if time_without == 0:
                return False, ["Cannot measure coverage overhead - base time is zero"]

            overhead = (time_with - time_without) / time_without

            if overhead > self.thresholds.max_coverage_overhead:
                return False, [f"Coverage overhead {overhead:.1%} > {self.thresholds.max_coverage_overhead:.1%} limit"]

            print(f"✓ Coverage overhead: {overhead:.1%} (acceptable)")
            return True, []

        except Exception as e:
            return False, [f"Failed to measure coverage overhead: {e}"]

    def generate_performance_report(self, unit_stats: TestExecutionStats,
                                  component_stats: TestExecutionStats) -> str:
        """Generate detailed performance report."""
        report = [
            "Performance Validation Report",
            "=" * 40,
            "",
            "Unit Tests:",
            f"  Total time: {unit_stats.total_time:.2f}s",
            f"  Test count: {unit_stats.test_count}",
            f"  Average per test: {unit_stats.avg_time_per_test:.3f}s",
            f"  Results: {unit_stats.passed} passed, {unit_stats.failed} failed, {unit_stats.skipped} skipped",
            "",
            "Component Tests:",
            f"  Total time: {component_stats.total_time:.2f}s",
            f"  Test count: {component_stats.test_count}",
            f"  Average per test: {component_stats.avg_time_per_test:.3f}s",
            f"  Results: {component_stats.passed} passed, {component_stats.failed} failed, {component_stats.skipped} skipped",
            "",
            f"Combined Total: {unit_stats.total_time + component_stats.total_time:.2f}s",
            f"Combined Tests: {unit_stats.test_count + component_stats.test_count}",
        ]

        # Add slowest tests
        if unit_stats.slowest_tests or component_stats.slowest_tests:
            report.extend([
                "",
                "Slowest Tests:",
            ])

            all_slow_tests = sorted(
                unit_stats.slowest_tests + component_stats.slowest_tests,
                key=lambda x: x[1],
                reverse=True
            )[:10]

            for test_name, duration in all_slow_tests:
                report.append(f"  {duration:.3f}s: {test_name}")

        return "\n".join(report)

    def save_performance_results(self, unit_stats: TestExecutionStats,
                               component_stats: TestExecutionStats) -> None:
        """Save performance results for trend analysis."""
        results = {
            "timestamp": time.time(),
            "unit_tests": {
                "total_time": unit_stats.total_time,
                "test_count": unit_stats.test_count,
                "passed": unit_stats.passed,
                "failed": unit_stats.failed,
                "avg_time_per_test": unit_stats.avg_time_per_test,
            },
            "component_tests": {
                "total_time": component_stats.total_time,
                "test_count": component_stats.test_count,
                "passed": component_stats.passed,
                "failed": component_stats.failed,
                "avg_time_per_test": component_stats.avg_time_per_test,
            },
            "thresholds": {
                "max_total_time": self.thresholds.max_total_time,
                "max_individual_test_time": self.thresholds.max_individual_test_time,
                "max_coverage_overhead": self.thresholds.max_coverage_overhead,
            }
        }

        with open(self.results_file, 'w') as f:
            json.dump(results, f, indent=2)

    def run_validation(self) -> bool:
        """Run complete performance validation."""
        print("Starting Performance Validation")
        print("=" * 40)

        # Run tests and collect stats
        unit_stats = self.run_unit_tests_timed()
        component_stats = self.run_component_tests_timed()

        # Validate performance thresholds
        perf_ok, perf_failures = self.validate_performance_thresholds(unit_stats, component_stats)

        # Validate coverage overhead
        coverage_ok, coverage_failures = self.validate_coverage_overhead()

        # Generate and display report
        report = self.generate_performance_report(unit_stats, component_stats)
        print(f"\n{report}")

        # Save results for trend analysis
        self.save_performance_results(unit_stats, component_stats)

        # Display validation results
        print(f"\n{'✅' if perf_ok else '❌'} Performance Requirements:")
        if perf_failures:
            for failure in perf_failures:
                print(f"  - {failure}")
        else:
            print("  All performance requirements met")

        print(f"\n{'✅' if coverage_ok else '❌'} Coverage Overhead:")
        if coverage_failures:
            for failure in coverage_failures:
                print(f"  - {failure}")
        else:
            print("  Coverage overhead within acceptable limits")

        return perf_ok and coverage_ok


def main():
    """Main entry point for performance validation."""
    project_root = Path(__file__).parent.parent
    validator = PerformanceValidator(project_root)

    success = validator.run_validation()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
