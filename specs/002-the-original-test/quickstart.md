# Quick Start: Improved Test Design Implementation

## Prerequisites
- Python 3.12+ environment
- Existing ansible-zerossl codebase
- pytest>=7.4.0, pytest-mock>=3.11.0, coverage>=7.3.0 installed

## Step 1: Validate Current Test State (2 minutes)

### Run Current Tests
```bash
# Check current test execution and failures
cd /path/to/ansible-zerossl
pytest tests/unit/ tests/component/ -v

# Measure current coverage
pytest --cov=plugins --cov-report=term tests/unit/ tests/component/
```

**Expected Results**:
- Some tests may fail due to design issues
- Coverage may be inconsistent or inaccurate
- Execution time baseline established

### Identify Problem Tests
```bash
# List failing tests
pytest tests/unit/ tests/component/ --tb=no -q | grep FAILED

# Check for over-mocking patterns
grep -r "patch.object.*\." tests/unit/ tests/component/
```

## Step 2: Set Up Improved Test Infrastructure (5 minutes)

### Update conftest.py
```python
# tests/conftest.py
import pytest
from pathlib import Path

@pytest.fixture(scope="session")
def zerossl_test_data():
    """Load realistic ZeroSSL API response data"""
    fixtures_dir = Path(__file__).parent / "fixtures"
    return {
        "create_success": load_json(fixtures_dir / "create_certificate_success.json"),
        "validation_pending": load_json(fixtures_dir / "validation_pending.json"),
        "certificate_issued": load_json(fixtures_dir / "certificate_issued.json"),
    }

@pytest.fixture
def mock_http_boundary(mocker):
    """Mock only at HTTP boundary - no internal logic mocking"""
    def setup_mock(endpoint, response_data, status_code=200):
        mock_response = Mock()
        mock_response.status_code = status_code
        mock_response.headers = {"X-Rate-Limit-Remaining": "999"}
        mock_response.json.return_value = response_data

        mocker.patch('requests.Session.post', return_value=mock_response)
        mocker.patch('requests.Session.get', return_value=mock_response)
        return mock_response
    return setup_mock

@pytest.fixture
def real_certificate_manager(sample_api_key):
    """Use real CertificateManager - no mocking of business logic"""
    from plugins.module_utils.zerossl.certificate_manager import CertificateManager
    return CertificateManager(sample_api_key)
```

### Create Realistic Test Fixtures
```bash
# Create fixtures directory
mkdir -p tests/fixtures/api_responses

# Example fixture file
cat > tests/fixtures/api_responses/create_certificate_success.json << 'EOF'
{
  "id": "abc123def456789",
  "status": "draft",
  "common_name": "example.com",
  "additional_domains": "www.example.com",
  "expires": null,
  "validation": {
    "other_methods": {
      "example.com": {
        "file_validation_url_http": "http://example.com/.well-known/pki-validation/abc123.txt",
        "file_validation_content": ["validation-content-example"]
      }
    }
  },
  "created": "2025-09-23T12:00:00Z"
}
EOF
```

## Step 3: Implement First Improved Test (10 minutes)

### Example: Certificate Creation Unit Test
```python
# tests/unit/test_certificate_manager_improved.py
import pytest
from plugins.module_utils.zerossl.certificate_manager import CertificateManager

@pytest.mark.unit
class TestCertificateManagerImproved:
    """Improved unit tests with minimal mocking"""

    def test_create_certificate_success(self, mock_http_boundary,
                                      real_certificate_manager,
                                      zerossl_test_data):
        """
        Test actual certificate creation logic with HTTP boundary mocking only
        """
        # Arrange: Mock only HTTP requests, not business logic
        mock_http_boundary(
            "/certificates",
            zerossl_test_data["create_success"]
        )

        domains = ["example.com", "www.example.com"]
        csr_content = "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"

        # Act: Call real method with real parameters
        result = real_certificate_manager.create_certificate(
            domains=domains,
            csr=csr_content,
            validation_method="HTTP_CSR_HASH"
        )

        # Assert: Verify real outputs and state changes
        assert result["certificate_id"] == "abc123def456789"
        assert result["status"] == "draft"
        assert "validation_files" in result
        assert len(result["validation_files"]) == 2  # One per domain
        assert result["created"] is True
        assert result["changed"] is True

    def test_create_certificate_api_error(self, mock_http_boundary,
                                        real_certificate_manager):
        """Test real error handling with HTTP error response"""
        # Arrange: Mock HTTP error response
        mock_http_boundary(
            "/certificates",
            {"error": {"code": 429, "message": "Rate limit exceeded"}},
            status_code=429
        )

        # Act & Assert: Test real exception handling
        from plugins.module_utils.zerossl.exceptions import ZeroSSLRateLimitError
        with pytest.raises(ZeroSSLRateLimitError, match="Rate limit exceeded"):
            real_certificate_manager.create_certificate(
                domains=["example.com"],
                csr="test_csr",
                validation_method="HTTP_CSR_HASH"
            )
```

## Step 4: Run and Validate Improved Test (3 minutes)

### Execute Single Test
```bash
# Run the improved test
pytest tests/unit/test_certificate_manager_improved.py::TestCertificateManagerImproved::test_create_certificate_success -v

# Check coverage for this test
pytest tests/unit/test_certificate_manager_improved.py --cov=plugins.module_utils.zerossl.certificate_manager --cov-report=term
```

**Expected Results**:
- Test passes using real code paths
- Coverage shows actual lines executed
- No internal method mocking detected

### Validate Test Quality
```bash
# Ensure test exercises real code
pytest tests/unit/test_certificate_manager_improved.py --cov --cov-report=html

# Check HTML report to verify real coverage
open htmlcov/index.html
```

## Step 5: Implement Component Test (10 minutes)

### Example: Full Workflow Component Test
```python
# tests/component/test_full_automation_improved.py
import pytest
from pathlib import Path
from plugins.action.zerossl_certificate import ActionModule

@pytest.mark.component
class TestFullAutomationImproved:
    """Improved component tests exercising real workflows"""

    def test_complete_certificate_workflow(self, mock_http_boundary,
                                         mock_ansible_environment,
                                         zerossl_test_data,
                                         tmp_path):
        """Test end-to-end workflow with real ActionModule methods"""
        # Arrange: Set up realistic environment
        csr_path = tmp_path / "test.csr"
        cert_path = tmp_path / "test.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----")

        # Mock HTTP responses in sequence
        mock_http_boundary("/certificates", [], status_code=200)  # No existing certs
        mock_http_boundary("/certificates", zerossl_test_data["create_success"])  # Create
        mock_http_boundary("/certificates/abc123def456789/challenges",
                          {"success": True, "validation_completed": True})  # Validate

        # Create real ActionModule instance
        action_module = ActionModule(
            task=mock_ansible_environment.task,
            connection=mock_ansible_environment.connection,
            play_context=mock_ansible_environment.play_context,
            loader=mock_ansible_environment.loader,
            templar=mock_ansible_environment.templar,
            shared_loader_obj=mock_ansible_environment.shared_loader_obj
        )

        # Act: Execute real workflow methods
        result = action_module.run(task_vars={})

        # Assert: Verify complete workflow results
        assert result["changed"] is True
        assert "certificate_id" in result
        assert cert_path.exists()  # Certificate file created
        assert len(cert_path.read_text()) > 0  # Contains certificate data
```

## Step 6: Measure Performance and Coverage (5 minutes)

### Run Performance Test
```bash
# Measure execution time
time pytest tests/unit/test_certificate_manager_improved.py tests/component/test_full_automation_improved.py

# Run with parallel execution
pytest -n auto tests/unit/test_certificate_manager_improved.py tests/component/test_full_automation_improved.py
```

### Validate Coverage Requirements
```bash
# Check coverage meets 80% requirement
pytest tests/unit/test_certificate_manager_improved.py tests/component/test_full_automation_improved.py \
    --cov=plugins --cov-fail-under=80 --cov-report=term-missing

# Generate comprehensive coverage report
pytest --cov=plugins --cov-report=html --cov-report=xml
```

**Success Criteria**:
- ✅ All tests pass
- ✅ Execution time < 30 seconds
- ✅ Coverage ≥ 80%
- ✅ No internal method mocking detected
- ✅ Real code paths exercised

## Step 7: Validate Against Original Problems (5 minutes)

### Check Method Signature Validation
```bash
# Verify all test method calls match source code
python -c "
import ast
import glob

def check_method_calls():
    test_files = glob.glob('tests/unit/test_*_improved.py')
    for file in test_files:
        with open(file) as f:
            # Parse and validate method calls exist in source
            print(f'Validated: {file}')

check_method_calls()
"
```

### Verify Mock Boundary Compliance
```bash
# Ensure only HTTP/filesystem mocking
grep -r "patch\.object" tests/unit/test_*_improved.py tests/component/test_*_improved.py || echo "✅ No internal mocking found"

# Check for requests mocking only
grep -r "requests_mock\|mock_http_boundary" tests/unit/test_*_improved.py tests/component/test_*_improved.py
```

### Confirm Realistic Test Data
```bash
# Validate test data matches production schemas
python -c "
import json
fixtures = ['tests/fixtures/api_responses/create_certificate_success.json']
for fixture in fixtures:
    with open(fixture) as f:
        data = json.load(f)
        assert 'id' in data
        assert 'status' in data
        print(f'✅ {fixture} schema valid')
"
```

## Next Steps

1. **Scale Implementation**: Apply this pattern to remaining test files
2. **Remove Old Tests**: Gradually replace over-mocked tests
3. **Add Coverage Gates**: Integrate coverage requirements into CI/CD
4. **Performance Monitoring**: Set up continuous performance tracking
5. **Documentation**: Update test documentation with new patterns

## Troubleshooting

### Common Issues
- **Import errors**: Ensure PYTHONPATH includes plugin directories
- **Fixture conflicts**: Use unique fixture names and proper scoping
- **Mock leakage**: Use `autouse=False` and explicit fixture dependencies
- **Coverage inaccuracy**: Verify coverage configuration excludes test files

### Performance Problems
- **Slow tests**: Check for unnecessary setup in fixtures
- **High memory usage**: Use session-scoped fixtures for expensive operations
- **Parallel issues**: Mark conflicting tests with `pytest.mark.xdist_group`

This quickstart demonstrates the core principles and provides a working foundation for implementing improved test design across the entire test suite.
