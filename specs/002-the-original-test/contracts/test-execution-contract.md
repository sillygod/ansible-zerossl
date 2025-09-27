# Test Execution Contract

## Overview
This contract defines the expected behavior for all unit and component tests in the improved test suite.

## Test Method Contracts

### Unit Test Contract
```python
# Contract: test_<functionality>_<scenario>()
def test_certificate_creation_success():
    """
    GIVEN: Valid domains and CSR
    WHEN: CertificateManager.create_certificate() is called
    THEN: Real method is exercised with only HTTP mocks
    AND: Response matches actual ZeroSSL API format
    AND: Test completes in < 5 seconds
    AND: Contributes to 80%+ line coverage
    """
    pass
```

**Requirements**:
- Method name must match actual source code method
- Only mock at HTTP boundary (requests.Session)
- Use realistic ZeroSSL API response data
- Assert on actual return values and state changes
- Execute within individual time limits

### Component Test Contract
```python
# Contract: test_<workflow>_<end_to_end_scenario>()
def test_full_certificate_automation_new_cert():
    """
    GIVEN: No existing certificate for domains
    WHEN: Complete automation workflow runs
    THEN: All ActionModule methods called with real parameters
    AND: Only external API responses mocked
    AND: Full workflow tested end-to-end
    AND: State changes verified at each step
    """
    pass
```

**Requirements**:
- Test complete workflows through real code paths
- Mock only external APIs and file operations
- Verify state transitions and side effects
- Use parameterized fixtures for multiple scenarios

## Mock Boundary Contracts

### HTTP Request Mocking
```python
@pytest.fixture
def mock_zerossl_api(mocker):
    """
    CONTRACT: Mock ZeroSSL API at HTTP boundary only
    - Use realistic response formats
    - Include error scenarios
    - Match actual API status codes
    - Preserve response headers
    """
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {'X-Rate-Limit-Remaining': '999'}
    mock_response.json.return_value = REALISTIC_CREATE_RESPONSE

    mocker.patch('requests.Session.post', return_value=mock_response)
```

### File System Mocking
```python
@pytest.fixture
def mock_certificate_files(tmp_path):
    """
    CONTRACT: Mock file operations for certificates
    - Use temporary directories
    - Create realistic certificate content
    - Test file permissions and paths
    - Clean up after test completion
    """
    cert_file = tmp_path / "certificate.crt"
    cert_file.write_text(VALID_CERTIFICATE_PEM)
    return tmp_path
```

## Test Data Contracts

### Realistic API Response Format
```json
{
  "id": "abc123def456",
  "status": "issued",
  "common_name": "example.com",
  "additional_domains": "www.example.com,api.example.com",
  "expires": "2025-12-17T12:00:00Z",
  "validation": {
    "other_methods": {
      "example.com": {
        "file_validation_url_http": "http://example.com/.well-known/pki-validation/abc123.txt",
        "file_validation_content": ["validation-content-string"]
      }
    }
  }
}
```

### Certificate Data Format
```python
VALID_CERTIFICATE_PEM = """-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
...
-----END CERTIFICATE-----"""
```

## Performance Contracts

### Execution Time Limits
- **Individual test**: ≤ 5 seconds
- **Test module**: ≤ 15 seconds
- **Full suite**: ≤ 30 seconds
- **Coverage generation**: ≤ 3 seconds additional

### Coverage Requirements
- **Line coverage**: ≥ 80% for all modules
- **Branch coverage**: ≥ 70% where applicable
- **Function coverage**: 100% for public methods

## Error Handling Contracts

### Exception Testing
```python
def test_certificate_creation_api_error():
    """
    CONTRACT: Test real exception handling
    - Use actual exception types from source code
    - Test exception propagation through call stack
    - Verify error messages and context
    - Test recovery mechanisms where applicable
    """
    with pytest.raises(ZeroSSLHTTPError, match="rate limit exceeded"):
        # Test actual error handling logic
        pass
```

### Failure Scenarios
- Network timeouts (requests.Timeout)
- API rate limiting (429 status codes)
- Invalid certificate data (validation errors)
- File permission issues (filesystem errors)

## Test Organization Contracts

### File Naming Convention
- `test_<module_name>.py` for unit tests
- `test_<workflow_name>.py` for component tests
- `conftest.py` for shared fixtures
- `fixtures/` directory for test data

### Test Method Naming
- `test_<method>_<scenario>_<expected_outcome>`
- Use descriptive names that explain the test purpose
- Group related tests in test classes
- Use pytest markers for categorization (@pytest.mark.unit)

## Validation Contracts

### Pre-Test Validation
- Verify all mocked methods exist in source code
- Check test data matches production API schemas
- Validate fixture dependencies are available

### Post-Test Validation
- Measure actual line coverage achieved
- Check execution time within limits
- Verify no unintended side effects
- Confirm mock boundaries were respected
