# Ansible ZeroSSL Certificate Management Collection

A comprehensive Ansible collection for managing SSL certificates through the ZeroSSL API. This collection provides complete certificate lifecycle management including creation, validation, renewal, and deployment with enterprise-grade features.

[![Test Automation and Quality Gates](https://github.com/sillygod/ansible-zerossl/actions/workflows/test-automation.yml/badge.svg)](https://github.com/sillygod/ansible-zerossl/actions/workflows/test-automation.yml)
[![codecov](https://codecov.io/gh/sillygod/ansible-zerossl/branch/main/graph/badge.svg)](https://codecov.io/gh/sillygod/ansible-zerossl)
[![GitHub release](https://img.shields.io/github/release/sillygod/ansible-zerossl.svg)](https://github.com/sillygod/ansible-zerossl/releases)
[![License](https://img.shields.io/github/license/sillygod/ansible-zerossl.svg)](https://github.com/sillygod/ansible-zerossl/blob/main/LICENSE)

## Features

- **Complete Certificate Lifecycle**: Create, validate, download, and renew SSL certificates
- **Multiple Validation Methods**: HTTP-01 and DNS-01 domain validation
- **Multi-Domain Support**: Single domain, multi-domain (SAN), and wildcard certificates
- **Intelligent Caching**: Reduce API calls with smart caching mechanisms
- **Concurrent Operations**: Thread-safe operations with proper locking
- **Idempotent Behavior**: Ansible-compliant operations with proper change detection
- **Automatic Renewal**: Check and renew certificates based on expiration thresholds
- **Secure File Handling**: Proper file permissions and atomic operations
- **Comprehensive Error Handling**: Retry logic and detailed error reporting

## Requirements

- **Ansible**: 8.0 or later
- **Python**: 3.12 or later
- **ZeroSSL Account**: API access key required
- **Dependencies**: `requests`, `cryptography`, `dnspython`

## Installation

### Option 1: Install from Ansible Galaxy (Recommended)

```bash
ansible-galaxy collection install sillygod.zerossl
```

### Option 2: Install from GitHub

```bash
ansible-galaxy collection install git+https://github.com/sillygod/ansible-zerossl.git
```

### Option 3: Install from local build

```bash
# Clone and build the collection
git clone https://github.com/sillygod/ansible-zerossl.git
cd ansible-zerossl
ansible-galaxy collection build .
ansible-galaxy collection install sillygod-zerossl-*.tar.gz
```

### Verify Installation

```bash
ansible-galaxy collection list sillygod.zerossl
```

### Requirements File

Create a `requirements.yml` file for your project:

```yaml
---
collections:
  - name: sillygod.zerossl
    version: ">=1.0.0"
```

Then install with:

```bash
ansible-galaxy collection install -r requirements.yml
```

## Quick Start

### Basic Usage

```yaml
---
- name: Create SSL certificate
  sillygod.zerossl.zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
      - www.example.com
    state: present
    certificate_path: /etc/ssl/certs/example.com.crt
    private_key_path: /etc/ssl/private/example.com.key
    validation_method: HTTP_CSR_HASH
    web_root: /var/www/html
```

### Using Ansible Vault for API Key

```bash
# Store API key securely
ansible-vault create group_vars/all/vault.yml
```

```yaml
# vault.yml
vault_zerossl_api_key: your_actual_api_key_here
```

```yaml
# playbook.yml
---
- name: SSL Certificate Management
  hosts: webservers
  vars:
    zerossl_api_key: "{{ vault_zerossl_api_key }}"
  tasks:
    - name: Ensure SSL certificate exists
      sillygod.zerossl.zerossl_certificate:
        api_key: "{{ zerossl_api_key }}"
        domains: "{{ ssl_domains }}"
        state: present
        certificate_path: "{{ ssl_cert_path }}"
        private_key_path: "{{ ssl_key_path }}"
```

## Configuration

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `api_key` | string | ZeroSSL API access key |
| `domains` | list | List of domains for the certificate |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `state` | string | `present` | Desired certificate state |
| `validation_method` | string | `HTTP_CSR_HASH` | Domain validation method |
| `certificate_path` | path | - | Path to save certificate file |
| `private_key_path` | path | - | Path to save private key file |
| `ca_bundle_path` | path | - | Path to save CA bundle file |
| `full_chain_path` | path | - | Path to save full certificate chain |
| `validity_days` | int | `90` | Certificate validity period |
| `renew_threshold_days` | int | `30` | Days before expiration to renew |
| `timeout` | int | `30` | API request timeout in seconds |
| `force` | bool | `false` | Force certificate renewal |

### States

- **`present`**: Ensure certificate exists and is valid (default)
- **`request`**: Create certificate request and return validation challenges
- **`validate`**: Validate a pending certificate
- **`download`**: Download an issued certificate
- **`absent`**: Cancel/remove certificate
- **`check_renew_or_create`**: Check if certificate needs renewal

## Usage Examples

### Single Domain Certificate

```yaml
- name: Create single domain certificate
  sillygod.zerossl.zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
    state: present
    validation_method: HTTP_CSR_HASH
    certificate_path: /etc/ssl/certs/example.com.crt
    private_key_path: /etc/ssl/private/example.com.key
    web_root: /var/www/html
```

### Multi-Domain (SAN) Certificate

```yaml
- name: Create multi-domain certificate
  sillygod.zerossl.zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
      - www.example.com
      - api.example.com
      - blog.example.com
    state: present
    validation_method: HTTP_CSR_HASH
    certificate_path: /etc/ssl/certs/example.com.crt
    private_key_path: /etc/ssl/private/example.com.key
    ca_bundle_path: /etc/ssl/certs/example.com-ca.crt
    full_chain_path: /etc/ssl/certs/example.com-fullchain.crt
    web_root: /var/www/html
```

### Wildcard Certificate (DNS Validation)

```yaml
- name: Create wildcard certificate
  sillygod.zerossl.zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - "*.example.com"
    state: present
    validation_method: DNS_CSR_HASH
    certificate_path: /etc/ssl/certs/wildcard.example.com.crt
    private_key_path: /etc/ssl/private/wildcard.example.com.key
  register: cert_result

- name: Display DNS records for validation
  debug:
    msg: "Add DNS CNAME record: {{ item.cname_validation_p1 }} = {{ item.cname_validation_p2 }}"
  loop: "{{ cert_result.dns_records }}"
  when: cert_result.dns_records is defined
```

### Split Workflow (Request, Validate, Download)

```yaml
# Step 1: Request certificate
- name: Request certificate
  sillygod.zerossl.zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
    state: request
    validation_method: HTTP_CSR_HASH
  register: cert_request

# Step 2: Place validation files (manual or automated)
- name: Place validation files
  copy:
    content: "{{ item.content }}"
    dest: "{{ web_root }}/{{ item.url_path }}"
    mode: '0644'
  loop: "{{ cert_request.validation_files }}"

# Step 3: Validate certificate
- name: Validate certificate
  sillygod.zerossl.zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    certificate_id: "{{ cert_request.certificate_id }}"
    state: validate
    validation_method: HTTP_CSR_HASH

# Step 4: Download certificate
- name: Download certificate
  sillygod.zerossl.zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    certificate_id: "{{ cert_request.certificate_id }}"
    state: download
    certificate_path: /etc/ssl/certs/example.com.crt
    private_key_path: /etc/ssl/private/example.com.key
```

### Certificate Renewal Check

```yaml
- name: Check if certificate needs renewal
  sillygod.zerossl.zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
    state: check_renew_or_create
    renew_threshold_days: 30
  register: renewal_check

- name: Renew certificate if needed
  sillygod.zerossl.zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
    state: present
    force: true
  when: renewal_check.needs_renewal
```

### Advanced Configuration

```yaml
- name: Advanced certificate configuration
  sillygod.zerossl.zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains: "{{ app_domains }}"
    state: present
    validation_method: HTTP_CSR_HASH
    certificate_path: "{{ ssl_dir }}/{{ app_name }}.crt"
    private_key_path: "{{ ssl_dir }}/{{ app_name }}.key"
    ca_bundle_path: "{{ ssl_dir }}/{{ app_name }}-ca.crt"
    full_chain_path: "{{ ssl_dir }}/{{ app_name }}-fullchain.crt"
    validity_days: 90
    renew_threshold_days: 14
    timeout: 60
    file_mode: '0644'
    private_key_mode: '0600'
    web_root: "{{ web_document_root }}"
    enable_caching: true
  notify:
    - restart nginx
    - reload ssl certificates
```

## Return Values

The plugin returns comprehensive information about the certificate operation:

```yaml
{
  "changed": true,
  "certificate_id": "cert-123456789",
  "status": "issued",
  "domains": ["example.com", "www.example.com"],
  "expires": "2025-04-15 10:30:00",
  "validation_method": "HTTP_CSR_HASH",
  "files_created": [
    "/etc/ssl/certs/example.com.crt",
    "/etc/ssl/private/example.com.key"
  ],
  "validation_files": [
    {
      "domain": "example.com",
      "url_path": "/.well-known/pki-validation/validation-file.txt",
      "content": "validation-content-hash"
    }
  ],
  "dns_records": [
    {
      "cname_validation_p1": "A1B2C3D4E5F6.example.com",
      "cname_validation_p2": "A1B2C3D4E5F6.B2C3D4E5F6A1.C3D4E5F6A1B2.zerossl.com"
    }
  ],
  "msg": "Certificate created successfully"
}
```

## Error Handling

The plugin provides detailed error information for troubleshooting:

```yaml
{
  "failed": true,
  "msg": "Certificate validation failed",
  "error": {
    "type": "ZeroSSLValidationError",
    "message": "Domain validation failed for example.com",
    "details": {
      "domain": "example.com",
      "validation_method": "HTTP_CSR_HASH",
      "error_code": 10301
    },
    "retryable": true,
    "retry_after": 300
  }
}
```

## Best Practices

### Security

1. **Use Ansible Vault** for API keys:
   ```bash
   ansible-vault encrypt_string 'your_api_key' --name 'zerossl_api_key'
   ```

2. **Set proper file permissions**:
   ```yaml
   private_key_mode: '0600'  # Private keys
   file_mode: '0644'         # Certificates
   ```

3. **Use secure directories**:
   ```yaml
   certificate_path: /etc/ssl/certs/example.com.crt
   private_key_path: /etc/ssl/private/example.com.key
   ```

### Performance

1. **Enable caching** for repeated operations:
   ```yaml
   enable_caching: true
   ```

2. **Use appropriate timeouts**:
   ```yaml
   timeout: 60  # For slow networks
   ```

3. **Batch operations** when possible:
   ```yaml
   domains:
     - example.com
     - www.example.com
     - api.example.com  # Single certificate for multiple domains
   ```

### Reliability

1. **Set appropriate renewal thresholds**:
   ```yaml
   renew_threshold_days: 30  # Renew 30 days before expiration
   ```

2. **Use check mode** for testing:
   ```bash
   ansible-playbook ssl-playbook.yml --check
   ```

3. **Monitor certificate expiration**:
   ```yaml
   - name: Check certificate status
     sillygod.zerossl.zerossl_certificate:
       api_key: "{{ zerossl_api_key }}"
       domains: "{{ ssl_domains }}"
       state: check_renew_or_create
     register: cert_status
   ```

## Troubleshooting

### Common Issues

1. **Domain validation failures**:
   - Ensure validation files are accessible via HTTP
   - Check firewall and DNS settings
   - Verify web server configuration

2. **DNS validation issues**:
   - Verify DNS CNAME records are properly set with correct format (cname_validation_p1 → cname_validation_p2)
   - Allow time for DNS propagation
   - Check TTL values

3. **File permission errors**:
   - Ensure Ansible has write access to target directories
   - Check parent directory permissions
   - Verify disk space availability

4. **API rate limiting**:
   - Implement retry logic in playbooks
   - Use caching to reduce API calls
   - Monitor rate limit headers

### Debug Mode

Enable verbose output for troubleshooting:

```bash
ansible-playbook ssl-playbook.yml -vvv
```

### Validation Commands

Test validation file accessibility:

```bash
curl -I http://example.com/.well-known/pki-validation/validation-file.txt
```

Check DNS CNAME records:

```bash
dig CNAME A1B2C3D4E5F6.example.com
```

## Collection Information

### Modules Included

- **sillygod.zerossl.zerossl_certificate**: Main module for SSL certificate management

### Plugin Types

- **Action Plugin**: `sillygod.zerossl.zerossl_certificate`
- **Module Utils**: ZeroSSL API client and certificate management utilities

### Ansible Collection Metadata

- **Namespace**: `community`
- **Collection Name**: `zerossl`
- **Version**: `1.0.0`
- **Minimum Ansible Version**: `8.0.0`

## API Reference

For detailed API documentation, see the [ZeroSSL API Documentation](https://zerossl.com/documentation/api/).

## Testing Strategy

This project implements a comprehensive three-tier testing approach:

### Test Structure

```
tests/
├── unit/           # Unit tests - fast, isolated, mocked dependencies
├── component/      # Component tests - workflow testing with mocked APIs
├── integration/    # Integration tests - real ZeroSSL API calls ⚠️
├── fixtures/       # Test data and helpers
├── security/       # Security-focused tests
├── performance/    # Performance and load tests
└── compatibility/ # Ansible version compatibility tests
```

### Test Categories

| Type | Speed | API Calls | When to Run | Purpose |
|------|-------|-----------|-------------|---------|
| **Unit** | Very Fast (<1s) | None (mocked) | Always | Test individual components |
| **Component** | Fast (1-5s) | None (mocked) | Pre-commit, CI | Test workflow integration |
| **Integration** | Slow (30s+) | Real API calls | Manual, releases | Test real API integration |

### Running Different Test Types

```bash
# Development workflow (fast feedback)
pytest tests/unit/ -x

# Pre-commit checks (comprehensive but fast)
pytest tests/unit/ tests/component/ --cov=plugins/

# Pre-release validation (manual, uses API quota)
pytest tests/integration/ -v -s

# Full test suite (development only)
pytest --cov=plugins/ --cov-report=html
```

For detailed testing documentation, see [tests/README.md](tests/README.md).

## Contributing

1. Fork the repository at [sillygod/ansible-zerossl](https://github.com/sillygod/ansible-zerossl)
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality (unit and component tests required)
5. Ensure fast tests pass: `pytest tests/unit/ tests/component/`
6. Submit a pull request

### Development Setup

```bash
git clone https://github.com/sillygod/ansible-zerossl.git
cd ansible-zerossl

./dev-setup.sh
```

If you want to customize the ansible.cfg for your own settings, you can run =git update-index --skip-worktree ansible.cfg= to ignore changes.

### Running Tests

The project uses a three-tier testing strategy:

```bash
# Install development dependencies
pip install -r requirements.txt

# Fast tests (CI-safe) - Unit and component tests with mocks
pytest tests/unit/ tests/component/ -v

# Run all tests except integration (recommended for development)
pytest -m "not integration" -v

# Run specific test categories
pytest tests/unit/ -v          # Unit tests - isolated components
pytest tests/component/ -v     # Component tests - workflow with mocks
pytest tests/integration/ -v   # Integration tests - real ZeroSSL API ⚠️
pytest tests/performance/ -v   # Performance and load tests
pytest tests/security/ -v      # Security-focused tests

# Run with coverage (fast tests only)
pytest tests/unit/ tests/component/ --cov=plugins/ --cov-report=html
```

#### Integration Tests (Real API Testing)

Integration tests make real API calls to ZeroSSL and require environment setup:

```bash
# Set up environment for integration tests
export ZEROSSL_API_KEY="your_actual_api_key"
export ZEROSSL_TEST_DOMAINS="test.yourdomain.com,api.yourdomain.com"

# Run integration tests (uses real API quota)
pytest tests/integration/ -v -s

# Skip integration tests (default behavior)
pytest -m "not integration" -v
```

**⚠️ Warning**: Integration tests use real ZeroSSL API quota and require domains you control for validation. Use sparingly.

### Building the Collection

```bash
# Build collection artifact
ansible-galaxy collection build

# Install locally for testing
ansible-galaxy collection install sillygod-zerossl-*.tar.gz --force
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/sillygod/ansible-zerossl/issues)
- **Community**: [Ansible Community Forum](https://forum.ansible.com/)
- **Galaxy**: [Ansible Galaxy Page](https://galaxy.ansible.com/community/zerossl)

## Changelog

See [CHANGELOG.md](docs/CHANGELOG.md) for version history and release notes.

## Acknowledgments

- [ZeroSSL](https://zerossl.com/) for providing the SSL certificate API
- [Ansible](https://ansible.com/) for the automation framework
- The open-source community for contributions and feedback
- [Spec kit](https://github.com/github/spec-kit)

 This repo uses spec kits to do major refactor and tests for the original code base.
