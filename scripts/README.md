# Test Automation Scripts

This directory contains automation scripts for test execution, coverage measurement, performance validation, and quality gates.

## Scripts Overview

### `coverage_automation.py`
Implements comprehensive coverage measurement automation following the coverage contract.

**Features:**
- Unit and component test execution with coverage
- Multiple coverage report formats (HTML, XML, JSON, terminal)
- Coverage target validation per module
- Performance requirement validation
- Automated coverage summary generation

**Usage:**
```bash
python scripts/coverage_automation.py
# or
make coverage-automation
```

**Requirements:**
- Minimum 80% overall coverage
- Module-specific coverage targets (see contract)
- Performance overhead ≤ 20%

### `performance_validation.py`
Validates test suite performance against contract requirements.

**Features:**
- Test execution time measurement
- Individual test performance analysis
- Coverage overhead measurement
- Parallel execution performance testing
- Performance trend tracking

**Usage:**
```bash
python scripts/performance_validation.py
# or
make performance
```

**Requirements:**
- Total execution time ≤ 30 seconds
- Individual test time ≤ 5 seconds
- Coverage overhead ≤ 20%

### `test_quality_gates.py`
Enforces test quality standards and prevents over-mocking regression.

**Features:**
- Mock boundary violation detection
- Forbidden internal mocking detection
- Real code path validation
- Test method coverage analysis
- Quality gate enforcement

**Usage:**
```bash
python scripts/test_quality_gates.py
# or
make quality-gates
```

**Quality Standards:**
- Only HTTP/filesystem boundary mocking allowed
- No internal business logic mocking
- Real code path execution required
- Method signature compliance

## Integration with CI/CD

### GitHub Actions
The scripts are integrated into `.github/workflows/test-automation.yml` for:
- Automated quality gate enforcement
- Performance monitoring
- Coverage tracking
- Multi-Python version testing

### Local Development
Use the Makefile targets for local development:

```bash
# Quick development check
make quick

# Full CI simulation
make ci-simulation

# Complete validation
make validate

# Individual components
make quality-gates
make performance
make coverage-automation
```

## Configuration

### Coverage Targets
Configured in `scripts/coverage_automation.py`:
```python
COVERAGE_TARGETS = {
    "plugins.action.zerossl_certificate": 85,
    "plugins.module_utils.zerossl.certificate_manager": 90,
    "plugins.module_utils.zerossl.api_client": 85,
    "plugins.module_utils.zerossl.validation_handler": 80,
    "plugins.module_utils.zerossl.exceptions": 70,
}
```

### Performance Thresholds
Configured in `scripts/performance_validation.py`:
```python
class PerformanceThresholds:
    max_total_time: float = 30.0  # seconds
    max_individual_test_time: float = 5.0  # seconds
    max_coverage_overhead: float = 0.2  # 20% overhead
```

### Quality Gates
Configured in `scripts/test_quality_gates.py`:
- Allowed mock boundaries (HTTP, filesystem)
- Forbidden mock patterns (internal methods)
- Real code path requirements

## Output Files

The scripts generate the following output files:

- `coverage.xml` - XML coverage report for CI/CD
- `coverage.json` - JSON coverage data for analysis
- `htmlcov/` - HTML coverage report for viewing
- `quality_gate_results.json` - Quality gate analysis results
- `performance_results.json` - Performance validation results

## Troubleshooting

### Common Issues

1. **Coverage targets not met**
   - Check which modules need more test coverage
   - Ensure tests exercise real code paths
   - Remove unnecessary exclusions

2. **Performance validation failures**
   - Identify slow tests with `--durations=0`
   - Consider test parallelization
   - Optimize test fixtures and setup

3. **Quality gate violations**
   - Review mock usage in test files
   - Ensure only HTTP/filesystem mocking
   - Add real code path testing

4. **CI/CD failures**
   - Run `make ci-simulation` locally first
   - Check GitHub Actions logs for specific errors
   - Verify all dependencies are installed

### Debug Mode

Enable verbose output by modifying script parameters or adding debug flags to pytest commands in the Makefile.

## Contract Compliance

These scripts implement the following contracts:
- Coverage Measurement Contract (`specs/002-the-original-test/contracts/coverage-measurement-contract.md`)
- Test Execution Contract (`specs/002-the-original-test/contracts/test-execution-contract.md`)

All validation follows the established requirements for test quality, performance, and coverage standards.
