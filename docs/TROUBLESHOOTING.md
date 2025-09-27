# Troubleshooting Guide for ZeroSSL Plugin Test Design

This guide addresses common test design issues, debugging techniques, and solutions for the ZeroSSL Ansible plugin test suite.

## Table of Contents

1. [Common Test Issues](#common-test-issues)
2. [HTTP Boundary Mocking Problems](#http-boundary-mocking-problems)
3. [Coverage Issues](#coverage-issues)
4. [Performance Problems](#performance-problems)
5. [Quality Gate Violations](#quality-gate-violations)
6. [CI/CD Issues](#cicd-issues)
7. [Local Development Problems](#local-development-problems)
8. [Debugging Techniques](#debugging-techniques)
9. [Error Messages and Solutions](#error-messages-and-solutions)
10. [Best Practices Reminders](#best-practices-reminders)

## Common Test Issues

### 1. Tests Pass Locally But Fail in CI

**Symptoms**:
- Tests work fine on local machine
- Same tests fail in GitHub Actions
- Inconsistent results between runs

**Common Causes & Solutions**:

#### Environment Differences
```bash
# Check Python version consistency
python --version
# Should match CI configuration (3.12)

# Check dependency versions
pip freeze | grep -E "(pytest|ansible|requests)"
```

**Solution**: Ensure local environment matches CI:
```bash
# Update to match CI dependencies
pip install ansible>=8.0.0 pytest>=7.4.0 requests>=2.31.0
```

#### Timing Issues
```python
# PROBLEM: Tests depend on execution order
def test_a(self):
    self.shared_state = "value"

def test_b(self):
    assert self.shared_state == "value"  # Fails if test_a doesn't run first
```

**Solution**: Make tests independent:
```python
# SOLUTION: Use fixtures for shared state
@pytest.fixture
def shared_state():
    return "value"

def test_a(self, shared_state):
    assert shared_state == "value"

def test_b(self, shared_state):
    assert shared_state == "value"
```

#### File Path Issues
```python
# PROBLEM: Hardcoded paths
def test_file_operation(self):
    with open("/Users/user/test.txt", "r") as f:  # Fails in CI
        content = f.read()
```

**Solution**: Use relative paths and fixtures:
```python
# SOLUTION: Use temp directories
def test_file_operation(self, temp_directory):
    test_file = temp_directory / "test.txt"
    test_file.write_text("content")
    assert test_file.read_text() == "content"
```

### 2. Mock Not Working as Expected

**Symptoms**:
- Mock calls aren't being intercepted
- Real HTTP requests being made
- Unexpected responses in tests

#### Mock Setup Order Issues
```python
# PROBLEM: Mock setup after object creation
def test_bad_mock_order(self, mocker):
    api_client = ZeroSSLAPIClient("api_key")  # Creates session
    mocker.patch('requests.Session.get')  # Too late!
```

**Solution**: Set up mocks before object creation:
```python
# SOLUTION: Mock before instantiation
def test_good_mock_order(self, mock_http_boundary):
    mock_http_boundary('/certificates', {'id': 'test'})
    api_client = ZeroSSLAPIClient("api_key")  # Now uses mock
```

#### Incorrect Mock Target
```python
# PROBLEM: Mocking wrong target
mocker.patch('requests.get')  # But code uses Session.get
```

**Solution**: Use HTTP boundary mocking:
```python
# SOLUTION: Use our boundary mocking fixture
mock_http_boundary('/certificates', response_data)  # Handles Session correctly
```

### 3. Fixture Not Found Errors

**Symptoms**:
```
pytest.fixture 'mock_http_boundary' not found
```

**Common Causes & Solutions**:

#### Missing Import
```python
# Add to test file if needed
import pytest
```

#### Conftest.py Not Loaded
- Ensure `conftest.py` exists in `tests/` directory
- Check for syntax errors in `conftest.py`
- Verify fixture is properly defined

#### Scope Issues
```python
# PROBLEM: Scope mismatch
@pytest.fixture(scope="session")
def session_fixture():
    return "value"

def test_needs_function_scope(self, session_fixture):
    session_fixture.append("new")  # Can't modify session-scoped fixture
```

**Solution**: Use appropriate scope:
```python
# SOLUTION: Function scope for mutable fixtures
@pytest.fixture
def function_fixture():
    return ["value"]
```

## HTTP Boundary Mocking Problems

### 1. Multiple Endpoint Conflicts

**Symptoms**:
- Wrong responses for different endpoints
- `/certificates/123` returning data for `/certificates/456`

```python
# PROBLEM: Overlapping endpoint patterns
mock_http_boundary('/certificates', response1)
mock_http_boundary('/certificates/123', response2)  # May conflict
```

**Solution**: Use specific endpoints first:
```python
# SOLUTION: Most specific patterns first
mock_http_boundary('/certificates/123', specific_response)
mock_http_boundary('/certificates', general_response)
```

### 2. Scenario Mocking Not Working

**Symptoms**:
- `mock_http_boundary('scenario')` not working
- Getting default responses instead of scenario responses

**Debug Steps**:
```python
# Check available scenarios
print(mock_zerossl_api_responses.keys())

# Verify scenario exists
assert 'your_scenario' in mock_zerossl_api_responses
```

**Common Solutions**:
- Add missing scenario to `tests/fixtures/zerossl_responses.py`
- Use correct scenario name (case-sensitive)
- Ensure scenario has all required response data

### 3. Response Format Issues

**Symptoms**:
- JSON parsing errors
- Wrong response structure

```python
# PROBLEM: Incorrect response format
mock_http_boundary('/certificates', "string_response")  # Should be dict
```

**Solution**: Use proper response format:
```python
# SOLUTION: Use dictionary responses
mock_http_boundary('/certificates', {
    'id': 'cert123',
    'status': 'draft',
    'domains': ['example.com']
})
```

## Coverage Issues

### 1. Coverage Too Low

**Symptoms**:
```
FAIL Required test coverage of 80% not reached. Total coverage: 45%
```

**Debug Coverage**:
```bash
# Generate detailed coverage report
pytest --cov=plugins.action --cov=plugins.module_utils \
  --cov-report=html --cov-report=term-missing

# Open HTML report
open htmlcov/index.html
```

**Common Solutions**:

#### Missing Test Cases
- Check `htmlcov/` report for uncovered lines
- Add tests for error conditions
- Test edge cases and boundary conditions

#### Wrong Coverage Target
```bash
# Check what's being measured
pytest --cov=wrong.module  # Won't find anything

# Fix: Use correct module paths
pytest --cov=plugins.action --cov=plugins.module_utils
```

#### Exclusion Issues
```python
# Add exclusions for untestable code
if TYPE_CHECKING:  # pragma: no cover
    pass

def __repr__(self):  # pragma: no cover
    return f"<{self.__class__.__name__}>"
```

### 2. Coverage Overreporting

**Symptoms**:
- Coverage shows 100% but not all code is tested
- Mock returns prevent real code execution

```python
# PROBLEM: Mock bypasses real code
@patch('certificate_manager.create_certificate')
def test_bypassed_code(self, mock_create):
    mock_create.return_value = {'id': 'test'}
    # Real create_certificate method never runs!
```

**Solution**: Use HTTP boundary mocking:
```python
# SOLUTION: Mock only HTTP boundaries
def test_real_code(self, mock_http_boundary, real_certificate_manager):
    mock_http_boundary('/certificates', {'id': 'test'})
    # Real create_certificate method executes
    result = real_certificate_manager.create_certificate(...)
```

### 3. Module Not Found in Coverage

**Symptoms**:
```
CoverageWarning: Module plugins.action was never imported
```

**Solutions**:
- Ensure tests actually import the modules
- Check module paths are correct
- Add imports in test files or conftest.py

## Performance Problems

### 1. Tests Too Slow

**Symptoms**:
- Individual tests taking >5 seconds
- Total test suite >30 seconds
- Timeout errors

**Debug Performance**:
```bash
# Show slowest tests
pytest --durations=10

# Profile specific test
pytest tests/unit/test_slow.py --durations=0
```

**Common Causes & Solutions**:

#### Real Network Requests
```python
# PROBLEM: Actually hitting external APIs
def test_slow_network(self):
    response = requests.get("https://api.zerossl.com/certificates")  # Real request!
```

**Solution**: Ensure proper mocking:
```python
# SOLUTION: Mock HTTP boundary
def test_fast_mock(self, mock_http_boundary):
    mock_http_boundary('/certificates', response_data)
    # No real network request
```

#### Expensive Setup
```python
# PROBLEM: Expensive setup in each test
def test_with_expensive_setup(self):
    large_data = generate_million_records()  # Slow!
    # test code
```

**Solution**: Use session-scoped fixtures:
```python
# SOLUTION: Generate once per session
@pytest.fixture(scope="session")
def large_data():
    return generate_million_records()

def test_with_cached_setup(self, large_data):
    # Uses cached data
```

#### File I/O in Tests
```python
# PROBLEM: Creating large files
def test_with_file_io(self):
    with open("large_file.txt", "w") as f:
        f.write("x" * 1000000)  # Slow file creation
```

**Solution**: Use in-memory alternatives:
```python
# SOLUTION: Use StringIO or small test data
from io import StringIO

def test_with_memory_io(self):
    data = StringIO("test content")
    # Much faster
```

### 2. Memory Issues

**Symptoms**:
- Tests running out of memory
- Gradual memory increase during test runs

**Common Causes & Solutions**:

#### Fixture Cleanup
```python
# PROBLEM: No cleanup
@pytest.fixture
def resource_leak():
    resource = expensive_resource()
    return resource  # No cleanup!
```

**Solution**: Use yield for cleanup:
```python
# SOLUTION: Automatic cleanup
@pytest.fixture
def clean_resource():
    resource = expensive_resource()
    yield resource
    resource.cleanup()  # Always runs
```

## Quality Gate Violations

### 1. Mock Boundary Violations

**Symptoms**:
```
Quality Gates: ❌ FAILED
Found mock boundary violation: mocker.patch('certificate_manager.method')
```

**Solution**: Replace with HTTP boundary mocking:
```python
# WRONG: Internal mocking
@patch('certificate_manager.create_certificate')
def test_wrong_mock(self, mock_create):
    pass

# RIGHT: HTTP boundary mocking
def test_right_mock(self, mock_http_boundary, real_certificate_manager):
    mock_http_boundary('/certificates', response_data)
```

### 2. No Real Code Paths

**Symptoms**:
```
No real code path testing detected
```

**Solution**: Use real object fixtures:
```python
# Add real object usage
def test_real_paths(self, real_api_client, mock_http_boundary):
    mock_http_boundary('/certificates', response_data)
    result = real_api_client.create_certificate(domains, csr)
    # Now exercises real code paths
```

### 3. Excessive Mock Objects

**Symptoms**:
```
Excessive mock object usage detected
```

**Solution**: Reduce Mock() usage:
```python
# WRONG: Too many Mock objects
def test_excessive_mocks(self):
    manager = Mock()
    manager.method = Mock()
    manager.method.return_value = Mock()

# RIGHT: Use real objects with boundary mocking
def test_minimal_mocks(self, mock_http_boundary, real_manager):
    mock_http_boundary('/endpoint', real_response_data)
    result = real_manager.method()
```

## CI/CD Issues

### 1. GitHub Actions Failures

**Symptoms**:
- Tests pass locally but fail in GitHub Actions
- Inconsistent CI results

**Debug Steps**:
```bash
# Check GitHub Actions logs
# Look for environment differences
# Verify dependency versions
```

**Common Solutions**:

#### Cache Issues
```yaml
# Clear cache in GitHub Actions
- name: Clear cache
  run: |
    rm -rf ~/.cache/pip
    pip cache purge
```

#### Environment Variables
```yaml
# Add missing environment variables
env:
  ANSIBLE_HOST_KEY_CHECKING: False
  ANSIBLE_RETRY_FILES_ENABLED: False
```

#### Timeout Issues
```yaml
# Increase timeout for slow tests
timeout-minutes: 15  # Default is 10
```

### 2. Coverage Reporting Failures

**Symptoms**:
- Coverage reports not uploading
- Codecov failures

**Solutions**:
```yaml
# Ensure coverage files exist
- name: Check coverage files
  run: |
    ls -la coverage.xml
    ls -la htmlcov/

# Upload with error handling
- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    fail_ci_if_error: false  # Don't fail CI on upload issues
```

### 3. Parallel Test Failures

**Symptoms**:
- Tests fail when run with `-n auto`
- Race conditions in parallel execution

**Solutions**:
```python
# Use unique temporary directories
@pytest.fixture
def unique_temp_dir(tmp_path):
    import uuid
    unique_dir = tmp_path / str(uuid.uuid4())
    unique_dir.mkdir()
    return unique_dir
```

## Local Development Problems

### 1. Virtual Environment Issues

**Symptoms**:
- Module not found errors
- Wrong Python version

**Solutions**:
```bash
# Verify virtual environment
which python
python --version

# Recreate if needed
rm -rf venv/
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Make Commands Not Working

**Symptoms**:
- `make test` fails
- Command not found errors

**Debug**:
```bash
# Check if make is available
which make

# Check Makefile syntax
make -n test  # Dry run

# Check working directory
pwd  # Should be project root
```

### 3. Import Errors

**Symptoms**:
```
ModuleNotFoundError: No module named 'plugins'
```

**Solutions**:
```bash
# Check PYTHONPATH
echo $PYTHONPATH

# Add project root to path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Or install in development mode
pip install -e .
```

## Debugging Techniques

### 1. Pytest Debugging Options

```bash
# Verbose output
pytest -v

# Show stdout/stderr
pytest -s

# Drop into debugger on failure
pytest --pdb

# Stop after first failure
pytest -x

# Show local variables in tracebacks
pytest --tb=long

# Run specific test method
pytest tests/unit/test_api_client.py::TestAPI::test_method -v
```

### 2. Mock Debugging

```python
# Check if mock was called
assert mock_http_boundary.called
assert mock_http_boundary.call_count == 2

# Check call arguments
print(mock_http_boundary.call_args)
print(mock_http_boundary.call_args_list)

# Reset mock between tests
mock_http_boundary.reset_mock()
```

### 3. Coverage Debugging

```bash
# See exactly what lines are missing
pytest --cov=module --cov-report=term-missing

# Get detailed branch coverage
pytest --cov=module --cov-branch --cov-report=html

# Debug why specific lines aren't covered
pytest --cov=module --cov-report=annotate
```

### 4. Performance Debugging

```bash
# Profile test execution
pytest --profile

# Memory profiling (if memory-profiler installed)
pytest --memory-profiler

# Line-by-line timing
python -m cProfile -s cumtime test_file.py
```

## Error Messages and Solutions

### Common Error Messages

#### `fixture 'mock_http_boundary' not found`
- **Cause**: Missing conftest.py or import issue
- **Solution**: Check conftest.py exists and is in correct location

#### `AssertionError: assert False is True`
- **Cause**: Test logic error or wrong expectations
- **Solution**: Debug with `print()` statements or `--pdb`

#### `requests.exceptions.ConnectionError`
- **Cause**: Real HTTP request instead of mock
- **Solution**: Ensure HTTP boundary mocking is set up correctly

#### `TypeError: 'Mock' object is not callable`
- **Cause**: Mock setup error
- **Solution**: Check mock configuration and call syntax

#### `Coverage failure: total of X% is less than fail-under=80%`
- **Cause**: Insufficient test coverage
- **Solution**: Add tests for uncovered code paths

### Quality Gate Error Messages

#### `Found mock boundary violation`
- **Cause**: Internal method mocking detected
- **Solution**: Replace with HTTP boundary mocking

#### `No real code path testing detected`
- **Cause**: All business logic is mocked
- **Solution**: Use real object fixtures

#### `Performance requirement not met`
- **Cause**: Tests taking too long
- **Solution**: Optimize slow tests or use session-scoped fixtures

## Best Practices Reminders

### 1. Test Design

✅ **DO**:
- Use HTTP boundary mocking only
- Test real business logic
- Keep tests independent
- Use descriptive test names
- Test error conditions

❌ **DON'T**:
- Mock internal business methods
- Create interdependent tests
- Use hardcoded paths or values
- Skip error testing
- Write slow tests without reason

### 2. Mock Usage

✅ **DO**:
```python
# HTTP boundary mocking
mock_http_boundary('/endpoint', response_data)

# Filesystem mocking
mocker.patch('pathlib.Path.write_text')

# External service mocking
mocker.patch('dns.resolver.Resolver.query')
```

❌ **DON'T**:
```python
# Internal method mocking
certificate_manager.create_certificate = Mock()

# Excessive Mock objects
result = Mock().method().return_value = Mock()
```

### 3. Debugging Strategy

1. **Start Simple**: Run single test first
2. **Check Mocks**: Verify mocks are being called
3. **Examine Output**: Use `-s` flag to see print statements
4. **Step Through**: Use `--pdb` for interactive debugging
5. **Check Environment**: Ensure consistent environment setup

### 4. Performance Optimization

1. **Profile First**: Use `--durations=10` to find slow tests
2. **Cache Data**: Use session-scoped fixtures for expensive setup
3. **Mock External**: Ensure no real network calls
4. **Minimize I/O**: Use in-memory alternatives when possible

### 5. Quality Maintenance

1. **Run Quality Gates**: Use `make quality-gates` regularly
2. **Monitor Coverage**: Check coverage trends over time
3. **Review Performance**: Validate execution time requirements
4. **Update Documentation**: Keep troubleshooting guide current

## Getting Help

### 1. Check Documentation
- Read `docs/TESTING.md` for comprehensive guidelines
- Review `scripts/README.md` for automation help

### 2. Run Diagnostics
```bash
# Check overall health
make validate

# Quick quality check
make quality-gates

# Performance check
make performance
```

### 3. Debug Systematically
1. Isolate the failing test
2. Check for environment differences
3. Verify mock setup
4. Review recent changes
5. Compare with working examples

### 4. Common Commands for Debugging
```bash
# Test single method with full output
pytest tests/unit/test_api_client.py::TestAPI::test_method -v -s --tb=long

# Check coverage for specific module
pytest tests/unit/test_api_client.py --cov=plugins.module_utils.zerossl.api_client --cov-report=term-missing

# Performance profile
pytest tests/unit/test_api_client.py --durations=0

# Quality gate check
python scripts/test_quality_gates.py
```

Remember: When in doubt, follow the established patterns in existing tests and refer to the comprehensive test documentation.
