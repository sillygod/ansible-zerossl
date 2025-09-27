# Testing Documentation for ZeroSSL Ansible Plugin

This document provides comprehensive guidelines for testing the ZeroSSL Ansible plugin, including new test patterns, boundary mocking principles, and best practices.

## Table of Contents

1. [Overview](#overview)
2. [Test Architecture](#test-architecture)
3. [HTTP Boundary Mocking](#http-boundary-mocking)
4. [Test Categories](#test-categories)
5. [Writing Tests](#writing-tests)
6. [Coverage Requirements](#coverage-requirements)
7. [Performance Standards](#performance-standards)
8. [Quality Gates](#quality-gates)
9. [Local Development](#local-development)
10. [CI/CD Integration](#cicd-integration)
11. [Troubleshooting](#troubleshooting)

## Overview

The ZeroSSL plugin testing framework follows modern testing principles with emphasis on:

- **HTTP Boundary Mocking**: Mock only at external API boundaries
- **Real Business Logic Testing**: Exercise actual code paths without internal mocking
- **Contract-Driven Development**: Validate against established contracts
- **Performance Standards**: Ensure fast, reliable test execution
- **Quality Gates**: Prevent regression in test quality

## Test Architecture

### Directory Structure

```
tests/
├── conftest.py                    # Shared fixtures and configuration
├── fixtures/
│   ├── api_responses/            # ZeroSSL API response data
│   ├── certificate_data/         # PEM certificate fixtures
│   └── zerossl_responses.py      # Mock response constants
├── unit/                         # Unit tests with HTTP boundary mocking
│   ├── test_api_client.py        # ZeroSSL API client tests
│   ├── test_certificate_manager.py  # Certificate management logic
│   ├── test_validation_handler.py   # Domain validation tests
│   └── test_plugin_contract.py   # Ansible plugin contract tests
└── component/                    # Component tests with real workflows
    ├── test_full_automation.py   # End-to-end certificate workflows
    ├── test_error_handling.py    # Error propagation testing
    ├── test_multi_domain.py      # SAN certificate scenarios
    ├── test_renewal_check.py     # Certificate renewal logic
    ├── test_security.py          # Security validation
    └── test_split_workflow.py    # Workflow state transitions
```

### Test Fixtures

#### Core Fixtures (conftest.py)

```python
@pytest.fixture
def mock_http_boundary(mocker, mock_zerossl_api_responses):
    """
    Mock only at HTTP boundary - supports dual API:
    - Unit tests: mock_http_boundary('/endpoint', response_data, status_code)
    - Component tests: mock_http_boundary('scenario')
    """

@pytest.fixture
def real_api_client(sample_api_key):
    """Real ZeroSSLAPIClient instance for testing actual code paths."""

@pytest.fixture
def real_certificate_manager(sample_api_key):
    """Real CertificateManager instance for business logic testing."""
```

## HTTP Boundary Mocking

### Core Principle

**ONLY mock at HTTP boundaries** - never mock internal business logic methods.

### Allowed Mock Boundaries

✅ **HTTP Requests**
```python
# Correct: Mock external HTTP calls
mock_http_boundary('/certificates', CERTIFICATE_CREATED_RESPONSE)
```

✅ **Filesystem Operations**
```python
# Correct: Mock file system operations
mocker.patch('pathlib.Path.write_text')
mocker.patch('pathlib.Path.read_text')
```

✅ **External Services**
```python
# Correct: Mock DNS resolution
mocker.patch('dns.resolver.Resolver.query')
```

### Forbidden Internal Mocking

❌ **Business Logic Methods**
```python
# WRONG: Never mock internal methods
certificate_manager._create_certificate = Mock()  # ❌
api_client.validate_certificate = Mock()          # ❌
```

❌ **State Management**
```python
# WRONG: Never mock state handling
action_module._handle_present_state = Mock()      # ❌
```

### HTTP Boundary Mock API

#### Unit Test Style (Old API)
```python
def test_certificate_creation(mock_http_boundary, real_api_client):
    # Mock specific endpoint
    mock_http_boundary('/certificates', {
        'id': 'cert123',
        'status': 'draft',
        'domains': ['example.com']
    }, status_code=200)

    # Test real API client method
    result = real_api_client.create_certificate(['example.com'], csr_content)
    assert result['id'] == 'cert123'
```

#### Component Test Style (New API)
```python
def test_full_automation_workflow(mock_http_boundary, real_certificate_manager):
    # Mock scenario-based responses
    mock_http_boundary('new_certificate')

    # Test real workflow
    result = real_certificate_manager.automate_certificate_lifecycle(
        domains=['example.com'],
        validation_method='HTTP_CSR_HASH'
    )
    assert result['success'] is True
```

## Test Categories

### Unit Tests (`tests/unit/`)

**Purpose**: Test individual components with external dependencies mocked.

**Characteristics**:
- Mock only HTTP/filesystem boundaries
- Exercise real business logic
- Fast execution (≤1s per test)
- High coverage of code paths

**Example**:
```python
@pytest.mark.unit
def test_certificate_renewal_logic(mock_http_boundary, real_certificate_manager):
    """Test real renewal logic with mocked API responses."""
    # Mock API responses
    mock_http_boundary('/certificates', LIST_CERTIFICATES_WITH_EXPIRING)

    # Test real business logic
    needs_renewal = real_certificate_manager.needs_renewal(
        domains=['example.com'],
        threshold_days=30
    )

    assert needs_renewal is True
```

### Component Tests (`tests/component/`)

**Purpose**: Test integrated workflows with realistic scenarios.

**Characteristics**:
- Mock only external API calls
- Test complete user workflows
- Real file operations with temporary directories
- Moderate execution time (≤5s per test)

**Example**:
```python
@pytest.mark.component
def test_certificate_request_to_download_workflow(mock_http_boundary, temp_directory):
    """Test complete certificate workflow from request to download."""
    # Setup real CSR file
    csr_path = temp_directory / "test.csr"
    csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\n...")

    # Mock sequential API responses
    mock_http_boundary('success')

    # Test real ActionModule workflow
    action_module = ActionModule(...)
    result = action_module.run(task_vars={...})

    assert result['changed'] is True
    assert (temp_directory / "certificate.crt").exists()
```

## Writing Tests

### Test Method Naming

Follow descriptive naming that explains what is being tested:

```python
# Good: Describes what is tested
def test_certificate_renewal_threshold_calculation_with_valid_dates(self):

# Good: Describes the scenario
def test_api_client_retry_logic_on_rate_limit_error(self):

# Bad: Too generic
def test_certificate(self):
```

### Test Structure

Use the Arrange-Act-Assert pattern:

```python
def test_multi_domain_certificate_creation(self, mock_http_boundary, real_api_client):
    # Arrange
    domains = ['example.com', 'www.example.com', 'api.example.com']
    csr_content = "-----BEGIN CERTIFICATE REQUEST-----\n..."

    mock_http_boundary('/certificates', {
        'id': 'cert123',
        'status': 'draft',
        'domains': domains
    })

    # Act
    result = real_api_client.create_certificate(domains, csr_content)

    # Assert
    assert result['id'] == 'cert123'
    assert result['domains'] == domains
    assert len(result['validation_details']) == 3
```

### Parameterized Tests

Use parameterization for testing multiple scenarios:

```python
@pytest.mark.parametrize("domains,expected_count", [
    (['example.com'], 1),
    (['example.com', 'www.example.com'], 2),
    (['example.com', 'www.example.com', 'api.example.com'], 3),
])
def test_domain_validation_file_creation(self, domains, expected_count, temp_directory):
    # Test implementation
    pass
```

### Error Testing

Test error conditions with realistic API errors:

```python
def test_api_rate_limit_handling(self, mock_http_boundary, real_api_client):
    # Mock rate limit error
    mock_http_boundary('/certificates', {
        'error': {
            'code': 429,
            'type': 'rate_limit_exceeded',
            'message': 'API rate limit exceeded'
        }
    }, status_code=429)

    # Test error handling
    with pytest.raises(ZeroSSLHTTPError) as exc_info:
        real_api_client.create_certificate(['example.com'], csr_content)

    assert 'rate limit' in str(exc_info.value).lower()
    assert hasattr(exc_info.value, 'retry_after')
```

## Coverage Requirements

### Module-Specific Targets

```python
COVERAGE_TARGETS = {
    "plugins.action.zerossl_certificate": 85,      # Core action module
    "plugins.module_utils.zerossl.certificate_manager": 90,  # Business logic
    "plugins.module_utils.zerossl.api_client": 85,  # HTTP client
    "plugins.module_utils.zerossl.validation_handler": 80,  # Validation logic
    "plugins.module_utils.zerossl.exceptions": 70,  # Exception classes
}
```

### Coverage Commands

```bash
# Unit tests with coverage
pytest tests/unit/ --cov=plugins.action --cov=plugins.module_utils \
  --cov-report=html --cov-report=term-missing --cov-fail-under=80

# Component tests with coverage
pytest tests/component/ --cov=plugins.action --cov=plugins.module_utils \
  --cov-append --cov-report=html --cov-report=term-missing

# Full coverage automation
python scripts/coverage_automation.py
```

### Coverage Exclusions

```python
# Exclude from coverage
if TYPE_CHECKING:  # pragma: no cover
    pass

def __repr__(self):  # pragma: no cover
    return f"<{self.__class__.__name__}>"

if __name__ == "__main__":  # pragma: no cover
    main()
```

## Performance Standards

### Execution Time Limits

- **Individual tests**: ≤5 seconds
- **Unit test suite**: ≤15 seconds
- **Component test suite**: ≤15 seconds
- **Total execution**: ≤30 seconds
- **Coverage overhead**: ≤20%

### Performance Optimization

```python
# Use session-scoped fixtures for expensive setup
@pytest.fixture(scope="session")
def expensive_setup():
    # Setup that takes time
    pass

# Use lazy evaluation
@pytest.fixture
def cached_api_responses():
    if not hasattr(cached_api_responses, '_cache'):
        cached_api_responses._cache = load_api_responses()
    return cached_api_responses._cache
```

### Performance Monitoring

```bash
# Monitor test performance
pytest --durations=10

# Run performance validation
python scripts/performance_validation.py
```

## Quality Gates

### Automated Validation

```bash
# Run all quality gates
python scripts/test_quality_gates.py

# Check for mocking violations
make quality-gates
```

### Quality Standards

1. **Mock Boundary Compliance**: Only HTTP/filesystem mocking allowed
2. **Real Code Path Exercise**: Tests must call actual business logic
3. **Method Signature Compliance**: Test signatures must match source code
4. **Performance Requirements**: All tests within time limits
5. **Coverage Targets**: Module-specific coverage goals met

### Quality Gate Violations

Common violations and fixes:

```python
# VIOLATION: Internal method mocking
certificate_manager._create_certificate = Mock()

# FIX: Use HTTP boundary mocking
mock_http_boundary('/certificates', CERTIFICATE_CREATED_RESPONSE)

# VIOLATION: No real code paths
action_module = Mock()

# FIX: Use real ActionModule
action_module = ActionModule(task=task, connection=connection, ...)
```

## Local Development

### Development Commands

```bash
# Quick test during development
make quick

# Run all tests
make test

# Run with coverage
make coverage

# Validate changes (like CI)
make validate

# Simulate CI pipeline
make ci-simulation
```

### Test-Driven Development

1. Write contract tests first (should fail)
2. Implement minimal code to pass tests
3. Add comprehensive test coverage
4. Refactor with confidence

### Debugging Tests

```bash
# Run specific test with verbose output
pytest tests/unit/test_api_client.py::test_specific_method -v -s

# Debug with pdb
pytest tests/unit/test_api_client.py::test_specific_method --pdb

# Show test durations
pytest --durations=0
```

## CI/CD Integration

### GitHub Actions Workflow

The testing workflow includes:

1. **Quality Gates**: Mock boundary and code quality validation
2. **Unit Tests**: Fast execution with coverage reporting
3. **Component Tests**: Workflow integration testing
4. **Parallel Execution**: Multi-core test execution
5. **Coverage Reporting**: Codecov integration
6. **Performance Monitoring**: Execution time validation

### Workflow Triggers

- Push to main/develop branches
- Pull requests
- Daily scheduled runs (2 AM UTC)

### Failure Handling

- Quality gate failures block the pipeline
- Coverage drops below threshold fail the build
- Performance regression failures block merge
- Security scan failures require review

## Test Markers

Use pytest markers to categorize tests:

```python
@pytest.mark.unit          # Unit tests
@pytest.mark.component     # Component tests
@pytest.mark.integration   # Integration tests (external APIs)
@pytest.mark.slow         # Tests taking >5 seconds
@pytest.mark.network      # Tests requiring network access
@pytest.mark.contract     # Contract validation tests
```

### Running Specific Test Categories

```bash
# Run only unit tests
pytest -m unit

# Run fast tests only
pytest -m "not slow"

# Run tests requiring network
pytest -m network

# Exclude integration tests
pytest -m "not integration"
```

## Best Practices Summary

### DO ✅

- Mock only at HTTP/filesystem boundaries
- Exercise real business logic in tests
- Use descriptive test names
- Test error conditions with realistic scenarios
- Maintain high coverage with meaningful tests
- Keep tests fast and reliable
- Follow the existing test patterns

### DON'T ❌

- Mock internal business logic methods
- Create tests that don't exercise real code
- Write slow tests without good reason
- Use excessive Mock objects
- Skip error testing
- Ignore coverage requirements
- Break established test patterns

## Migration from Old Patterns

If you encounter old test patterns, update them following these guidelines:

### Before (Old Pattern)
```python
# BAD: Internal mocking
def test_old_pattern(self, mocker):
    manager = CertificateManager('api_key')
    manager._create_certificate = mocker.Mock(return_value={'id': 'test'})

    result = manager.create_certificate(['example.com'], 'csr')
    assert result['id'] == 'test'
```

### After (New Pattern)
```python
# GOOD: HTTP boundary mocking
def test_new_pattern(self, mock_http_boundary, real_certificate_manager):
    mock_http_boundary('/certificates', {'id': 'test', 'status': 'draft'})

    result = real_certificate_manager.create_certificate(['example.com'], 'csr')
    assert result['id'] == 'test'
```

This testing documentation ensures consistent, high-quality test development that follows the established patterns and maintains the quality standards achieved through the test redesign project.
