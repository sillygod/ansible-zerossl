# Research Phase: Ansible ZeroSSL Plugin Development

## Ansible Plugin Architecture Decisions

### Decision: Action Plugin Architecture
**Rationale**: Use Ansible Action Plugin over Module Plugin because:
- Need local processing for CSR generation and certificate handling
- Requires file operations on control node for validation files
- Complex workflow management (request → validate → download)
- Better integration with existing Ansible patterns

**Alternatives considered**: Module Plugin - rejected because it would require all operations to occur on target hosts

### Decision: Python 3.12 with Modern Features
**Rationale**:
- Full type annotation support for better code quality
- Enhanced error handling with improved exception details
- Better async/await support for concurrent operations
- F-string improvements for cleaner string formatting

**Alternatives considered**: Python 3.8+ for broader compatibility - rejected because we want to leverage latest features

### Decision: Plugin Structure and Standards
**Implementation approach**:
```python
# Standard Ansible Action Plugin structure
from ansible.plugins.action import ActionBase
from ansible.errors import AnsibleActionFail

class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        # Implement certificate lifecycle management
        pass
```

**Standards compliance**:
- Follow DOCUMENTATION/EXAMPLES/RETURN documentation patterns
- Implement proper parameter validation using AnsibleModule patterns
- Use ansible.module_utils for shared functionality
- Provide comprehensive error messages with to_native() conversion

## ZeroSSL API Integration Decisions

### Decision: Comprehensive API Coverage
**Rationale**: Support full certificate lifecycle:
1. **Certificate Creation**: POST `/certificates` with CSR and domains
2. **Status Monitoring**: GET `/certificates/{id}` with polling
3. **Domain Validation**: Support both HTTP-01 and DNS-01 methods
4. **Certificate Download**: GET `/certificates/{id}/download`

**API Parameters**:
```python
# Certificate creation
{
    'certificate_domains': 'example.com,www.example.com',
    'certificate_csr': csr_content,
    'certificate_validity_days': 90,
    'validation_method': 'HTTP_CSR_HASH'
}
```

### Decision: Robust Error Handling and Rate Limiting
**Rationale**:
- ZeroSSL has rate limits (300 requests/day free tier)
- Need exponential backoff for status polling
- Implement retry logic for transient failures
- Handle 429 (rate limit) and 401 (auth) errors gracefully

**Implementation strategy**:
```python
def _api_request_with_retry(self, endpoint, method='GET', max_retries=3):
    for attempt in range(max_retries):
        try:
            response = self._execute_module('uri', {...})
            if response.status_code == 429:
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
            return response
        except Exception as e:
            if attempt == max_retries - 1:
                raise AnsibleActionFail(f"API request failed: {e}")
```

### Decision: Multi-Domain and Validation Support
**Rationale**: Support enterprise use cases:
- SAN certificates for multiple domains
- Both HTTP-01 (file-based) and DNS-01 (TXT record) validation
- Automatic validation file placement for HTTP-01
- Configurable validation timeouts

## Testing Strategy Decisions

### Decision: Comprehensive Test Coverage with Pytest
**Rationale**:
- Unit tests for core certificate operations
- Integration tests with ZeroSSL API (using test keys)
- Contract tests to verify API compatibility
- Mock tests for offline development

**Test structure**:
```
tests/
├── unit/
│   ├── test_certificate_manager.py
│   ├── test_validation_handler.py
│   └── test_api_client.py
├── integration/
│   ├── test_full_certificate_lifecycle.py
│   └── test_api_integration.py
└── fixtures/
    ├── sample_csr.pem
    └── mock_responses.json
```

### Decision: TDD Approach with Failing Tests First
**Implementation plan**:
1. Write contract tests that define expected API behavior
2. Create integration tests for user scenarios
3. Write unit tests for individual components
4. Implement code to make tests pass

## Architecture and Design Decisions

### Decision: Modular Design with Separation of Concerns
**Components**:
1. **CertificateManager**: Core certificate lifecycle operations
2. **ValidationHandler**: Domain validation logic (HTTP-01/DNS-01)
3. **APIClient**: ZeroSSL API communication with retry logic
4. **ConfigValidator**: Parameter validation and sanitization

**Rationale**: Enables independent testing, easier maintenance, and clear responsibility boundaries

### Decision: Idempotent Operations
**Implementation approach**:
- Check existing certificate status before creating new ones
- Support renewal threshold configuration
- Compare domain lists to avoid duplicate certificates
- Return appropriate changed/unchanged status

**Example logic**:
```python
def ensure_certificate_present(self, domains, renewal_days=30):
    existing_cert = self._find_existing_certificate(domains)
    if existing_cert and not self._needs_renewal(existing_cert, renewal_days):
        return {'changed': False, 'certificate': existing_cert}
    # Proceed with certificate creation/renewal
```

### Decision: Configuration and Security
**Security considerations**:
- API keys stored in Ansible Vault
- Certificate files with appropriate permissions (600)
- Temporary files cleaned up after operations
- No logging of sensitive data

**Configuration validation**:
```python
def validate_parameters(self, params):
    required_params = ['api_key', 'domains']
    for param in required_params:
        if not params.get(param):
            raise AnsibleActionFail(f"Missing required parameter: {param}")

    # Validate domain format
    for domain in params['domains']:
        if not self._is_valid_domain(domain):
            raise AnsibleActionFail(f"Invalid domain format: {domain}")
```

## Performance and Scalability Decisions

### Decision: Concurrent Operation Support
**Rationale**: Support enterprise environments with many domains
- Implement safe concurrent certificate operations
- Use file locking for shared resources
- Optimize API calls to minimize rate limit impact

### Decision: Caching and State Management
**Implementation**:
- Cache certificate status to reduce API calls
- Store validation tokens temporarily for HTTP-01 challenges
- Implement state files for long-running operations

## Documentation and Examples

### Decision: Comprehensive Documentation
**Required sections**:
- DOCUMENTATION with all parameters and examples
- EXAMPLES covering common use cases
- RETURN documenting all possible return values
- README with installation and usage instructions

This research phase provides the foundation for implementing a robust, standards-compliant Ansible ZeroSSL plugin that meets enterprise requirements while following modern development practices.
