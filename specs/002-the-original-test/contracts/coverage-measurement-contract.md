# Coverage Measurement Contract

## Overview
This contract defines how test coverage will be measured, reported, and validated for the improved test suite.

## Coverage Configuration Contract

### pytest.ini Configuration
```ini
[tool:pytest]
addopts =
    --cov=plugins.action
    --cov=plugins.module_utils
    --cov-report=term-missing
    --cov-report=html:htmlcov
    --cov-fail-under=80
    --cov-branch
    -v

markers =
    unit: Unit tests
    component: Component tests
    slow: Tests that take longer than 1 second
```

### Coverage Target Contract
```python
# Module-level coverage requirements
COVERAGE_TARGETS = {
    "plugins.action.zerossl_certificate": 85,  # Core action module
    "plugins.module_utils.zerossl.certificate_manager": 90,  # Business logic
    "plugins.module_utils.zerossl.api_client": 85,  # HTTP client
    "plugins.module_utils.zerossl.validation_handler": 80,  # Validation logic
    "plugins.module_utils.zerossl.exceptions": 70,  # Exception classes
}
```

## Execution Contract

### Coverage Command Interface
```bash
# Unit tests only with coverage
pytest tests/unit/ --cov --cov-report=term

# Component tests with coverage
pytest tests/component/ --cov --cov-append --cov-report=term

# Full coverage report generation
pytest --cov --cov-report=html --cov-report=xml

# Parallel execution with coverage
pytest -n auto --cov --dist=loadfile
```

### Performance Requirements
- Coverage measurement overhead: ≤ 20% of base execution time
- Coverage report generation: ≤ 5 seconds
- HTML report generation: ≤ 10 seconds

## Coverage Validation Contract

### Minimum Thresholds
```python
@pytest.fixture(scope="session", autouse=True)
def validate_coverage_requirements():
    """
    Automatically validate coverage meets requirements
    Fails the test suite if coverage thresholds not met
    """
    def check_coverage():
        coverage_data = get_coverage_data()
        for module, target in COVERAGE_TARGETS.items():
            actual = coverage_data.get_line_coverage(module)
            assert actual >= target, f"{module} coverage {actual}% < {target}%"

    yield
    check_coverage()
```

### Coverage Quality Gates
- **Line Coverage**: ≥ 80% overall, module-specific targets above
- **Branch Coverage**: ≥ 70% for conditional logic
- **Function Coverage**: 100% for public API methods
- **Missing Lines**: Must be explicitly justified or covered

## Reporting Contract

### Terminal Output Format
```
Name                                      Stmts   Miss  Cover   Missing
--------------------------------------------------------------------
plugins/action/zerossl_certificate.py      150      8    95%   45-52
plugins/module_utils/zerossl/api_client.py  200     15    92%   312-318, 445
plugins/module_utils/zerossl/manager.py     180     10    94%   78-85
--------------------------------------------------------------------
TOTAL                                       530     33    94%
```

### HTML Report Contract
- **Module breakdown**: Coverage per source file
- **Line-by-line**: Highlighting covered/uncovered lines
- **Branch analysis**: Conditional coverage details
- **Trends**: Coverage changes over time
- **Missing coverage**: Specific lines that need tests

### XML Report for CI/CD
```xml
<coverage version="7.3.0" timestamp="1632849600" line-rate="0.94" branch-rate="0.75">
  <sources>
    <source>/path/to/ansible-zerossl</source>
  </sources>
  <packages>
    <package name="plugins.action" line-rate="0.95" branch-rate="0.80">
      <classes>
        <class name="zerossl_certificate.py" filename="plugins/action/zerossl_certificate.py"
               line-rate="0.95" branch-rate="0.80">
          <methods/>
          <lines>
            <line number="1" hits="1"/>
            <line number="2" hits="1"/>
            <!-- ... -->
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
```

## Integration Contract

### CI/CD Pipeline Integration
```yaml
# Example GitHub Actions integration
- name: Run tests with coverage
  run: |
    pytest --cov --cov-report=xml --cov-report=term

- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
    fail_ci_if_error: true

- name: Coverage comment
  uses: py-cov-action/python-coverage-comment-action@v3
  with:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Coverage Enforcement
```python
# Fail tests if coverage drops below threshold
def test_coverage_regression():
    """Prevent coverage regression"""
    current_coverage = get_current_coverage()
    baseline_coverage = get_baseline_coverage()

    assert current_coverage >= baseline_coverage, \
        f"Coverage regression: {current_coverage}% < {baseline_coverage}%"
```

## Exclusion Contract

### Coverage Exclusions
```python
# Lines to exclude from coverage measurement
COVERAGE_EXCLUSIONS = [
    "pragma: no cover",     # Explicit exclusion
    "def __repr__",         # String representations
    "if self.debug:",       # Debug-only code
    "raise NotImplementedError",  # Abstract methods
    "if __name__ == .__main__.:", # Script entry points
    "class .*\\bProtocol\\):",    # Protocol definitions
]
```

### Excluded Files
- Test files (tests/*)
- Configuration files (setup.py, conftest.py)
- Development utilities
- Generated code

## Validation and Quality Assurance

### Coverage Accuracy Validation
```python
def test_coverage_accuracy():
    """Ensure coverage measurement is accurate"""
    # Test that covered lines are actually executed
    # Test that uncovered lines are actually missed
    # Validate branch coverage matches actual execution
    pass
```

### Coverage Report Validation
- Reports must be generated successfully
- All configured formats must be produced
- Coverage data must be consistent across formats
- Performance requirements must be met

### Continuous Monitoring
- Track coverage trends over time
- Alert on significant coverage drops
- Monitor test execution performance
- Validate coverage tool compatibility with new Python versions
