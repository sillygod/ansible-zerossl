# Ansible ZeroSSL Plugin Testing

This document describes the comprehensive testing strategy for the Ansible ZeroSSL certificate management plugin.

## Test Structure Overview

```
tests/
├── unit/                    # Unit tests - fast, isolated, mocked
├── component/               # Component tests - workflow testing with mocks
├── integration/             # Integration tests - real API calls ⚠️
├── fixtures/                # Test data and helpers
├── security/                # Security-focused tests
├── performance/             # Performance and load tests
├── compatibility/           # Ansible version compatibility tests
├── conftest.py             # Shared test configuration
└── README.md               # This file
```

## Test Categories

### 1. Unit Tests (`tests/unit/`)
**Purpose**: Test individual components in isolation
- **Speed**: Very fast (< 1 second per test)
- **Dependencies**: All external dependencies mocked
- **Network**: No network calls
- **When to run**: Always, on every change
- **Markers**: `@pytest.mark.unit`

```bash
# Run unit tests
pytest tests/unit/ -v

# Run unit tests with coverage
pytest tests/unit/ --cov=plugins/ --cov-report=html
```

### 2. Component Tests (`tests/component/`)
**Purpose**: Test how multiple components work together
- **Speed**: Fast (1-5 seconds per test)
- **Dependencies**: External APIs mocked, internal integration real
- **Network**: No external network calls
- **When to run**: Before commits, in CI
- **Markers**: `@pytest.mark.component`

```bash
# Run component tests
pytest tests/component/ -v

# Run specific component test
pytest tests/component/test_full_automation.py -v
```

### 3. Integration Tests (`tests/integration/`) ⚠️
**Purpose**: Test real integration with ZeroSSL API
- **Speed**: Slow (30+ seconds per test)
- **Dependencies**: Real ZeroSSL API, real domains
- **Network**: Real API calls, uses quota
- **When to run**: Manually, before releases
- **Markers**: `@pytest.mark.integration @pytest.mark.live`

```bash
# Set up environment
export ZEROSSL_API_KEY="your_api_key"
export ZEROSSL_TEST_DOMAINS="test.yourdomain.com"

# Run integration tests
pytest tests/integration/ -v -s
```

## Quick Testing Commands

```bash
# Run all tests except integration (CI-safe)
pytest -m "not integration" -v

# Run only fast tests (unit + component)
pytest tests/unit/ tests/component/ -v

# Run specific test type
pytest -m unit -v
pytest -m component -v
pytest -m integration -v

# Run with coverage
pytest tests/unit/ tests/component/ --cov=plugins/ --cov-report=term-missing

# Run tests matching pattern
pytest -k "test_certificate" -v

# Run tests and stop on first failure
pytest -x -v
```

## Environment Setup

### For Unit and Component Tests
```bash
# Install dependencies
pip install -r requirements-dev.txt

# No additional setup required
pytest tests/unit/ tests/component/
```

### For Integration Tests
```bash
# 1. Get ZeroSSL API key from https://app.zerossl.com/
export ZEROSSL_API_KEY="your_actual_api_key"

# 2. Set test domains you control
export ZEROSSL_TEST_DOMAINS="test.yourdomain.com,api.yourdomain.com"

# 3. Optional: Configure test behavior
export ZEROSSL_SKIP_MANUAL_VALIDATION="true"  # For automated testing
export ZEROSSL_CLEANUP_AFTER_TESTS="true"     # Clean up test certificates

# 4. Run tests
pytest tests/integration/ -v -s
```

## Test Markers

Tests are automatically marked based on directory and can be filtered:

| Marker | Description | Auto-applied |
|--------|-------------|--------------|
| `unit` | Unit tests | `tests/unit/` |
| `component` | Component tests | `tests/component/` |
| `integration` | Integration tests | `tests/integration/` |
| `live` | Tests requiring real API | `tests/integration/` |
| `slow` | Tests taking >30 seconds | Manual |
| `network` | Tests making network calls | Based on test name |
| `contract` | API contract tests | `tests/contract/` |

## CI/CD Configuration

### Recommended CI Pipeline

```yaml
# .github/workflows/test.yml example
name: Tests

on: [push, pull_request]

jobs:
  fast-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: |
          pip install -r requirements-dev.txt
      - name: Run unit and component tests
        run: |
          pytest tests/unit/ tests/component/ --cov=plugins/ --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  integration-tests:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule' || contains(github.event.head_commit.message, '[run-integration]')
    steps:
      - uses: actions/checkout@v3
      - name: Run integration tests
        env:
          ZEROSSL_API_KEY: ${{ secrets.ZEROSSL_API_KEY }}
          ZEROSSL_TEST_DOMAINS: ${{ secrets.ZEROSSL_TEST_DOMAINS }}
          ZEROSSL_SKIP_MANUAL_VALIDATION: "true"
        run: |
          pytest tests/integration/ -v
```

### Running Subsets

```bash
# Fast feedback loop (< 30 seconds)
pytest tests/unit/ -x

# Pre-commit checks (< 5 minutes)
pytest tests/unit/ tests/component/ --cov=plugins/

# Pre-release validation (manual, 30+ minutes)
pytest tests/integration/ -v -s

# Full test suite (manual only)
pytest --cov=plugins/ --cov-report=html
```

## Test Data and Fixtures

### Shared Fixtures (`tests/conftest.py`)
- Mock Ansible objects
- Sample API responses
- Temporary directories
- Test configuration

### Component-Specific Fixtures
- `tests/component/conftest.py` - Component test helpers
- `tests/integration/conftest_integration.py` - Live test setup
- `tests/fixtures/` - Sample certificates, API responses

### Creating Test Data
```python
# Use existing fixtures
def test_something(sample_api_key, temp_directory):
    pass

# Create custom data
@pytest.fixture
def custom_certificate_data():
    return {
        "id": "test_cert_123",
        "status": "issued",
        "domains": ["example.com"]
    }
```

## Debugging Tests

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure module paths are correct
   export PYTHONPATH="${PYTHONPATH}:$(pwd)"
   pytest tests/unit/test_api_client.py -v
   ```

2. **Mock Issues**
   ```python
   # Debug mock calls
   mock_method.assert_called_with(expected_args)
   print(f"Mock called with: {mock_method.call_args}")
   ```

3. **Integration Test Failures**
   ```bash
   # Check environment
   echo $ZEROSSL_API_KEY
   echo $ZEROSSL_TEST_DOMAINS

   # Run with verbose output
   pytest tests/integration/ -v -s --tb=long
   ```

### Test Output

```bash
# Verbose output with print statements
pytest -v -s

# Show local variables on failure
pytest --tb=long

# Drop into debugger on failure
pytest --pdb

# Only show test names
pytest --quiet

# Show coverage gaps
pytest --cov=plugins/ --cov-report=term-missing
```

## Performance Considerations

### Test Execution Times
- **Unit tests**: < 1s each, < 30s total
- **Component tests**: 1-5s each, < 5min total
- **Integration tests**: 30s-5min each, 30+ min total

### Optimization Tips
```bash
# Run tests in parallel (if using pytest-xdist)
pytest -n auto tests/unit/ tests/component/

# Run only failed tests from last run
pytest --lf

# Run tests until first failure
pytest -x

# Skip slow tests during development
pytest -m "not slow"
```

## Writing New Tests

### Test Organization
```python
# tests/unit/test_new_feature.py
import pytest
from unittest.mock import Mock, patch
from plugins.module_utils.zerossl.new_feature import NewFeature

@pytest.mark.unit
class TestNewFeature:
    """Test NewFeature component."""

    def test_basic_functionality(self):
        # Arrange
        feature = NewFeature()

        # Act
        result = feature.do_something()

        # Assert
        assert result == expected_value
```

### Best Practices
1. **Use descriptive test names**: `test_create_certificate_with_invalid_domain_returns_error`
2. **Follow AAA pattern**: Arrange, Act, Assert
3. **Mock external dependencies**: ZeroSSL API, file system, network
4. **Test edge cases**: Empty inputs, errors, timeouts
5. **Use appropriate markers**: `@pytest.mark.unit`, `@pytest.mark.slow`
6. **Keep tests focused**: One concept per test
7. **Use fixtures**: Reuse common setup code

## Continuous Integration

### GitHub Actions Integration
```yaml
# Run fast tests on every push
- name: Fast Tests
  run: pytest tests/unit/ tests/component/ --cov=plugins/

# Run integration tests nightly or on release
- name: Integration Tests
  if: github.event_name == 'schedule'
  env:
    ZEROSSL_API_KEY: ${{ secrets.ZEROSSL_API_KEY }}
  run: pytest tests/integration/
```

### Local Pre-commit Hook
```bash
# .git/hooks/pre-commit
#!/bin/bash
echo "Running fast tests..."
pytest tests/unit/ tests/component/ -q
if [ $? -ne 0 ]; then
    echo "Tests failed! Commit aborted."
    exit 1
fi
```

## Troubleshooting

### Common Problems

1. **"No module named 'plugins'"**
   - Add project root to PYTHONPATH
   - Run tests from project root directory

2. **Integration tests hang**
   - Check network connectivity
   - Verify API key validity
   - Increase timeouts in test config

3. **Rate limit errors**
   - Wait before retrying
   - Use separate API key for testing
   - Run integration tests less frequently

4. **Certificate validation failures**
   - Ensure test domains are accessible
   - Check domain ownership
   - Verify HTTP validation file placement

### Getting Help

- Check test output with `-v -s` flags
- Review test documentation in individual test files
- Check ZeroSSL API documentation for rate limits
- Verify environment variable setup

## Reporting Issues

When reporting test failures, include:
- Test command used
- Full error output
- Environment details (Python version, OS)
- API key permissions (don't include actual key)
- Domain ownership verification
