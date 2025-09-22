# ZeroSSL Ansible Plugin API Reference

Complete API reference for the ZeroSSL Ansible action plugin, including all parameters, return values, and configuration options.

## Table of Contents

- [Module Documentation](#module-documentation)
- [Parameters](#parameters)
- [Return Values](#return-values)
- [Examples](#examples)
- [Error Handling](#error-handling)
- [Internal API](#internal-api)

## Module Documentation

### zerossl_certificate

Manage SSL certificates using the ZeroSSL API.

**Synopsis:**
- Create, validate, download, and manage SSL certificates through the ZeroSSL API
- Supports both HTTP-01 and DNS-01 domain validation methods
- Provides complete certificate lifecycle management including automatic renewal
- Handles multi-domain (SAN) certificates and wildcard certificates
- Implements proper retry logic and rate limiting for robust operation

**Requirements:**
- Python 3.12 or later
- requests library
- cryptography library
- Valid ZeroSSL API key

## Parameters

### Required Parameters

#### api_key
- **Type**: `str`
- **Required**: `true`
- **Description**: ZeroSSL API access key
- **Security**: Store using Ansible Vault
- **Example**: `"sk_live_1234567890abcdef"`

#### domains
- **Type**: `list` of `str`
- **Required**: `true`
- **Description**: List of domains to include in the certificate
- **Notes**:
  - First domain becomes the common name
  - Additional domains are added as Subject Alternative Names (SAN)
  - Wildcard domains (*.example.com) require DNS validation
- **Example**: `["example.com", "www.example.com", "api.example.com"]`

### Optional Parameters

#### state
- **Type**: `str`
- **Default**: `"present"`
- **Choices**: `["present", "request", "validate", "download", "absent", "check_renew_or_create"]`
- **Description**: Desired state of the certificate
  - `present`: Ensure certificate exists and is valid, create/renew if needed
  - `request`: Create certificate request and return validation challenges
  - `validate`: Validate a pending certificate
  - `download`: Download an issued certificate
  - `absent`: Cancel/remove certificate
  - `check_renew_or_create`: Check if certificate needs renewal

#### validation_method
- **Type**: `str`
- **Default**: `"HTTP_CSR_HASH"`
- **Choices**: `["HTTP_CSR_HASH", "DNS_CSR_HASH"]`
- **Description**: Domain validation method
  - `HTTP_CSR_HASH`: HTTP-01 validation using file placement
  - `DNS_CSR_HASH`: DNS-01 validation using CNAME records
- **Notes**: DNS validation required for wildcard certificates

#### certificate_id
- **Type**: `str`
- **Description**: ZeroSSL certificate ID
- **Notes**: Required for validate, download states; optional for others (auto-discovered)

### File Path Parameters

#### certificate_path
- **Type**: `path`
- **Description**: Path to save the certificate file
- **Notes**: Required for download and present states; directory will be created if it doesn't exist

#### private_key_path
- **Type**: `path`
- **Description**: Path to save the private key file
- **Notes**: If not provided, private key is included in certificate_path

#### ca_bundle_path
- **Type**: `path`
- **Description**: Path to save the CA bundle file
- **Notes**: If not provided, CA bundle is included in certificate_path

#### full_chain_path
- **Type**: `path`
- **Description**: Path to save the full certificate chain
- **Notes**: Includes certificate + CA bundle for web servers

### CSR Parameters

#### csr_path
- **Type**: `path`
- **Description**: Path to existing Certificate Signing Request (CSR) file
- **Notes**: Required for request and present states if csr is not provided; must be in PEM format

#### csr
- **Type**: `str`
- **Description**: Certificate Signing Request content in PEM format
- **Notes**: Alternative to csr_path; if neither provided, CSR is auto-generated

### Certificate Configuration

#### validity_days
- **Type**: `int`
- **Default**: `90`
- **Choices**: `[90, 365]`
- **Description**: Certificate validity period in days

#### renew_threshold_days
- **Type**: `int`
- **Default**: `30`
- **Description**: Number of days before expiration to trigger renewal

### File Security Parameters

#### file_mode
- **Type**: `str`
- **Default**: `"0644"`
- **Description**: File permissions for certificate files (octal notation)

#### private_key_mode
- **Type**: `str`
- **Default**: `"0600"`
- **Description**: File permissions for private key files (octal notation)

### HTTP Validation Parameters

#### web_root
- **Type**: `path`
- **Description**: Web server document root for HTTP validation
- **Notes**: Required for HTTP_CSR_HASH validation method

#### auto_place_files
- **Type**: `bool`
- **Default**: `false`
- **Description**: Automatically place HTTP validation files

### Operational Parameters

#### timeout
- **Type**: `int`
- **Default**: `30`
- **Description**: API request timeout in seconds

#### force
- **Type**: `bool`
- **Default**: `false`
- **Description**: Force certificate renewal even if not needed

#### enable_caching
- **Type**: `bool`
- **Default**: `true`
- **Description**: Enable certificate information caching

## Return Values

### Common Return Values

#### changed
- **Type**: `bool`
- **Description**: Whether the task made changes
- **Example**: `true`

#### certificate_id
- **Type**: `str`
- **Description**: ZeroSSL certificate ID
- **Example**: `"cert-123456789"`

#### status
- **Type**: `str`
- **Description**: Current certificate status
- **Values**: `["draft", "pending_validation", "issued", "cancelled", "expired"]`

#### domains
- **Type**: `list` of `str`
- **Description**: List of domains in the certificate
- **Example**: `["example.com", "www.example.com"]`

#### expires
- **Type**: `str`
- **Description**: Certificate expiration date
- **Format**: `"YYYY-MM-DD HH:MM:SS"`
- **Example**: `"2025-04-15 10:30:00"`

#### msg
- **Type**: `str`
- **Description**: Human-readable message describing the result
- **Example**: `"Certificate created successfully"`

### State-Specific Return Values

#### For state: "request"

##### validation_files
- **Type**: `list` of `dict`
- **Description**: HTTP validation files to be placed
- **Structure**:
  ```yaml
  validation_files:
    - domain: "example.com"
      url_path: "/.well-known/pki-validation/validation-file.txt"
      content: "validation-content-hash"
      file_path: "/var/www/html/.well-known/pki-validation/validation-file.txt"
  ```

##### dns_records
- **Type**: `list` of `dict`
- **Description**: DNS CNAME records for validation
- **Structure**:
  ```yaml
  dns_records:
    - cname_validation_p1: "A1B2C3D4E5F6.example.com"
      cname_validation_p2: "A1B2C3D4E5F6.B2C3D4E5F6A1.C3D4E5F6A1B2.zerossl.com"
  ```

#### For state: "download" or "present"

##### files_created
- **Type**: `list` of `str`
- **Description**: List of files created or updated
- **Example**: `["/etc/ssl/certs/example.com.crt", "/etc/ssl/private/example.com.key"]`

##### certificate_info
- **Type**: `dict`
- **Description**: Certificate information
- **Structure**:
  ```yaml
  certificate_info:
    common_name: "example.com"
    additional_domains: "www.example.com,api.example.com"
    issuer: "ZeroSSL RSA Domain Secure Site CA"
    serial_number: "1234567890abcdef"
    fingerprint: "SHA1:AB:CD:EF..."
  ```

#### For state: "check_renew_or_create"

##### needs_renewal
- **Type**: `bool`
- **Description**: Whether certificate needs renewal
- **Example**: `false`

##### days_until_expiry
- **Type**: `int`
- **Description**: Days until certificate expires
- **Example**: `45`

### Error Return Values

#### failed
- **Type**: `bool`
- **Description**: Whether the task failed
- **Example**: `true`

#### error
- **Type**: `dict`
- **Description**: Detailed error information
- **Structure**:
  ```yaml
  error:
    type: "ZeroSSLValidationError"
    message: "Domain validation failed"
    details:
      domain: "example.com"
      validation_method: "HTTP_CSR_HASH"
      error_code: 10301
    retryable: true
    retry_after: 300
  ```

## Examples

### Basic Certificate Creation

```yaml
- name: Create basic certificate
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
    state: present
    certificate_path: /etc/ssl/certs/example.com.crt
    private_key_path: /etc/ssl/private/example.com.key
  register: result

- debug:
    var: result
```

**Return Value:**
```yaml
{
  "changed": true,
  "certificate_id": "cert-123456789",
  "status": "issued",
  "domains": ["example.com"],
  "expires": "2025-04-15 10:30:00",
  "files_created": [
    "/etc/ssl/certs/example.com.crt",
    "/etc/ssl/private/example.com.key"
  ],
  "msg": "Certificate created successfully"
}
```

### Request with Validation Information

```yaml
- name: Request certificate with validation info
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
      - www.example.com
    state: request
    validation_method: HTTP_CSR_HASH
  register: cert_request

- debug:
    msg: "Place file {{ item.file_path }} with content: {{ item.content }}"
  loop: "{{ cert_request.validation_files }}"
```

**Return Value:**
```yaml
{
  "changed": true,
  "certificate_id": "cert-123456789",
  "status": "draft",
  "domains": ["example.com", "www.example.com"],
  "validation_method": "HTTP_CSR_HASH",
  "validation_files": [
    {
      "domain": "example.com",
      "url_path": "/.well-known/pki-validation/validation-file1.txt",
      "content": "content-hash-123",
      "file_path": "/var/www/html/.well-known/pki-validation/validation-file1.txt"
    },
    {
      "domain": "www.example.com",
      "url_path": "/.well-known/pki-validation/validation-file2.txt",
      "content": "content-hash-456",
      "file_path": "/var/www/html/.well-known/pki-validation/validation-file2.txt"
    }
  ],
  "msg": "Certificate request created successfully"
}
```

### DNS Validation for Wildcard

```yaml
- name: Request wildcard certificate
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - "*.example.com"
    state: request
    validation_method: DNS_CSR_HASH
  register: wildcard_request

- debug:
    msg: "Add DNS CNAME record: {{ item.cname_validation_p1 }} = {{ item.cname_validation_p2 }}"
  loop: "{{ wildcard_request.dns_records }}"
```

**Return Value:**
```yaml
{
  "changed": true,
  "certificate_id": "cert-987654321",
  "status": "draft",
  "domains": ["*.example.com"],
  "validation_method": "DNS_CSR_HASH",
  "dns_records": [
    {
      "cname_validation_p1": "A1B2C3D4E5F6.example.com",
      "cname_validation_p2": "A1B2C3D4E5F6.B2C3D4E5F6A1.C3D4E5F6A1B2.zerossl.com"
    }
  ],
  "msg": "Certificate request created successfully"
}
```

### Renewal Check

```yaml
- name: Check certificate renewal status
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
    state: check_renew_or_create
    renew_threshold_days: 30
  register: renewal_status

- debug:
    var: renewal_status
```

**Return Value:**
```yaml
{
  "changed": false,
  "certificate_id": "cert-123456789",
  "status": "issued",
  "domains": ["example.com"],
  "expires": "2025-04-15 10:30:00",
  "needs_renewal": false,
  "days_until_expiry": 45,
  "msg": "Certificate does not need renewal"
}
```

## Error Handling

### Error Types

The plugin can return several types of errors:

#### ZeroSSLHTTPError
- **Description**: API communication errors
- **Retryable**: Usually yes
- **Example**:
  ```yaml
  error:
    type: "ZeroSSLHTTPError"
    message: "API request failed: HTTP 500 Internal Server Error"
    status_code: 500
    retryable: true
    retry_after: 60
  ```

#### ZeroSSLValidationError
- **Description**: Domain validation failures
- **Retryable**: Sometimes (depends on cause)
- **Example**:
  ```yaml
  error:
    type: "ZeroSSLValidationError"
    message: "Domain validation failed for example.com"
    validation_method: "HTTP_CSR_HASH"
    retryable: true
  ```

#### ZeroSSLRateLimitError
- **Description**: API rate limit exceeded
- **Retryable**: Yes (after delay)
- **Example**:
  ```yaml
  error:
    type: "ZeroSSLRateLimitError"
    message: "Rate limit exceeded"
    retry_after: 3600
    retryable: true
  ```

#### ZeroSSLConfigurationError
- **Description**: Invalid configuration or parameters
- **Retryable**: No
- **Example**:
  ```yaml
  error:
    type: "ZeroSSLConfigurationError"
    message: "Invalid domain name: invalid..domain.com"
    retryable: false
  ```

#### ZeroSSLFileSystemError
- **Description**: File system operation failures
- **Retryable**: Sometimes
- **Example**:
  ```yaml
  error:
    type: "ZeroSSLFileSystemError"
    message: "Cannot write to /etc/ssl/private/: Permission denied"
    file_path: "/etc/ssl/private/example.com.key"
    operation: "write"
    retryable: false
  ```

### Error Handling in Playbooks

```yaml
- name: Create certificate with error handling
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
    state: present
    certificate_path: /etc/ssl/certs/example.com.crt
  register: cert_result
  failed_when: false

- name: Handle different error types
  block:
    - debug:
        msg: "Certificate created successfully"
      when: not cert_result.failed

    - debug:
        msg: "Rate limit exceeded, retrying later"
      when:
        - cert_result.failed
        - cert_result.error.type == "ZeroSSLRateLimitError"

    - debug:
        msg: "Validation failed, check configuration"
      when:
        - cert_result.failed
        - cert_result.error.type == "ZeroSSLValidationError"

    - fail:
        msg: "Unrecoverable error: {{ cert_result.error.message }}"
      when:
        - cert_result.failed
        - not cert_result.error.retryable
```

## Internal API

### Module Utils Components

The plugin is built using several internal components:

#### ZeroSSLAPIClient
- **Purpose**: Low-level ZeroSSL API communication
- **Features**: Rate limiting, retry logic, error handling
- **Location**: `module_utils/zerossl/api_client.py`

#### CertificateManager
- **Purpose**: High-level certificate lifecycle management
- **Features**: Caching, renewal logic, file processing
- **Location**: `module_utils/zerossl/certificate_manager.py`

#### ValidationHandler
- **Purpose**: Domain validation preparation and processing
- **Features**: HTTP-01 and DNS-01 validation support
- **Location**: `module_utils/zerossl/validation_handler.py`

#### ConfigValidator
- **Purpose**: Parameter validation and sanitization
- **Features**: Input validation, compatibility checking
- **Location**: `module_utils/zerossl/config_validator.py`

### Caching System

#### CertificateCache
- **Purpose**: Intelligent caching of API responses
- **Features**: Memory and disk caching, TTL management
- **Configuration**:
  ```python
  cache = CertificateCache(
      cache_dir="/tmp/ansible-zerossl-cache",
      default_ttl=300,  # 5 minutes
      max_cache_size=100
  )
  ```

#### Cache Operations
- **get()**: Retrieve cached data
- **set()**: Store data in cache
- **invalidate()**: Remove specific cache entries
- **cleanup_expired()**: Remove expired entries

### Concurrency Management

#### ConcurrencyManager
- **Purpose**: Thread-safe operations and locking
- **Features**: Certificate locks, domain locks, file operation locks
- **Usage**:
  ```python
  with acquire_certificate_lock(cert_id, 'validation'):
      # Perform certificate operation
      pass
  ```

#### Lock Types
- **Certificate locks**: Prevent concurrent operations on same certificate
- **Domain locks**: Prevent concurrent operations on same domains
- **File locks**: Ensure atomic file operations

### Configuration

#### Environment Variables
- `ZEROSSL_API_KEY`: Default API key (use Ansible Vault instead)
- `ZEROSSL_CACHE_DIR`: Cache directory location
- `ZEROSSL_TIMEOUT`: Default API timeout

#### Ansible Configuration
```ini
# ansible.cfg
[defaults]
action_plugins = ./action_plugins
module_utils = ./module_utils

[zerossl]
cache_enabled = true
cache_ttl = 300
concurrent_operations = true
```

### Performance Considerations

#### API Rate Limits
- ZeroSSL: 5000 requests per hour per API key
- Plugin implements automatic rate limiting and backoff

#### Caching Strategy
- Certificate status: 2 minutes TTL
- Certificate lists: 5 minutes TTL
- Validation results: 1 minute TTL
- Downloads: 1 hour TTL (certificates don't change)

#### Concurrent Operations
- Multiple domains can be processed in parallel
- Same domain operations are serialized
- File operations use atomic writes with locking

### Security Features

#### API Key Protection
- Never logged or exposed in error messages
- Transmitted securely via HTTPS
- Stored only in memory during execution

#### File Security
- Private keys created with 0600 permissions
- Certificates created with 0644 permissions
- Atomic file operations with backup support
- Secure temporary file handling

#### Input Validation
- Domain name validation
- Path traversal prevention
- CSR content validation
- Parameter type checking
