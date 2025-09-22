# Quickstart Guide: Ansible ZeroSSL Plugin

This guide demonstrates the essential functionality of the Ansible ZeroSSL certificate management plugin through practical examples.

## Prerequisites

1. **ZeroSSL Account**: Sign up at [ZeroSSL](https://zerossl.com) and obtain API key
2. **Ansible**: Version 2.10+ installed
3. **Python**: 3.12+ with cryptography library
4. **Domain Access**: Control over domains for validation

## Installation

```bash
# Install the plugin (once implemented)
ansible-galaxy collection install community.zerossl

# Or for development
git clone <repository>
export ANSIBLE_ACTION_PLUGINS=$PWD/action_plugins
```

## Basic Usage Examples

### 1. Create and Deploy Certificate (Full Automation)

```yaml
- name: Obtain SSL certificate for website
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
      - www.example.com
    csr_path: /etc/ssl/certs/example.com.csr
    certificate_path: /etc/ssl/certs/example.com.crt
    state: present
    validation_method: HTTP_CSR_HASH
  register: cert_result

- name: Display certificate information
  debug:
    msg: "Certificate ID: {{ cert_result.certificate_id }}"
```

### 2. Split Workflow (Advanced Control)

```yaml
# Step 1: Request certificate
- name: Request certificate from ZeroSSL
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - blog.example.com
    csr_path: /etc/ssl/certs/blog.csr
    state: request
  register: cert_request

# Step 2: Place validation files
- name: Create validation file for HTTP-01 challenge
  copy:
    content: "{{ item.content }}"
    dest: "/var/www/html/.well-known/pki-validation/{{ item.filename }}"
    mode: '0644'
  loop: "{{ cert_request.validation_files }}"
  when: cert_request.validation_files is defined

# Step 3: Validate certificate
- name: Validate certificate
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    certificate_id: "{{ cert_request.certificate_id }}"
    state: validate

# Step 4: Download certificate
- name: Download issued certificate
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    certificate_id: "{{ cert_request.certificate_id }}"
    certificate_path: /etc/ssl/certs/blog.crt
    state: download
```

### 3. Certificate Renewal Check

```yaml
- name: Check if certificate needs renewal
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - api.example.com
    state: check_renew_or_create
    renew_threshold_days: 30
  register: renewal_check

- name: Renew certificate if needed
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - api.example.com
    csr_path: /etc/ssl/certs/api.csr
    certificate_path: /etc/ssl/certs/api.crt
    state: present
  when: renewal_check.needs_renewal
```

### 4. Multiple Domains (SAN Certificate)

```yaml
- name: Create multi-domain certificate
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - shop.example.com
      - checkout.example.com
      - payment.example.com
    csr_path: /etc/ssl/certs/shop-san.csr
    certificate_path: /etc/ssl/certs/shop-san.crt
    state: present
    validation_method: HTTP_CSR_HASH
```

### 5. DNS Validation (for Wildcard Certificates)

```yaml
- name: Request wildcard certificate with DNS validation
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - "*.example.com"
      - example.com
    csr_path: /etc/ssl/certs/wildcard.csr
    state: request
    validation_method: DNS_CSR_HASH
  register: dns_cert

- name: Display required DNS records
  debug:
    msg: |
      Add CNAME record for {{ item.domain }}:
      Name: {{ item.cname_validation_p1 }}
      Points To: {{ item.cname_validation_p2 }}
  loop: "{{ dns_cert.dns_records }}"
  when: dns_cert.dns_records is defined
```

## Security Best Practices

### 1. Secure API Key Storage

```yaml
# Use Ansible Vault for API keys
- name: Load encrypted variables
  include_vars: vault.yml

# vault.yml (encrypted)
zerossl_api_key: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  66386439653162336464...
```

### 2. Certificate File Permissions

```yaml
- name: Set secure permissions on certificate
  file:
    path: "{{ certificate_path }}"
    mode: '0600'
    owner: root
    group: root
  when: cert_result.changed
```

### 3. Cleanup Temporary Files

```yaml
- name: Clean up CSR file
  file:
    path: "{{ csr_path }}"
    state: absent
  when: cert_result.changed and cleanup_csr | default(true)
```

## Error Handling

### 1. Graceful Failure Handling

```yaml
- name: Obtain certificate with error handling
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains: "{{ cert_domains }}"
    csr_path: "{{ csr_path }}"
    certificate_path: "{{ cert_path }}"
    state: present
  register: cert_result
  failed_when: false

- name: Handle certificate errors
  debug:
    msg: "Certificate operation failed: {{ cert_result.msg }}"
  when: cert_result.failed

- name: Retry on rate limit
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains: "{{ cert_domains }}"
    csr_path: "{{ csr_path }}"
    certificate_path: "{{ cert_path }}"
    state: present
  when: cert_result.failed and cert_result.error_type == 'http' and cert_result.retryable
  delay: 300  # Wait 5 minutes before retry
```

### 2. Validation Troubleshooting

```yaml
- name: Verify web server can serve validation files
  uri:
    url: "{{ item.http_validation_url }}"
    method: GET
  loop: "{{ cert_request.validation_files }}"
  when: cert_request.validation_files is defined
  register: validation_check
  failed_when: false

- name: Report validation file accessibility
  debug:
    msg: "Validation file {{ item.item.filename }} is {{ 'accessible' if item.status == 200 else 'not accessible' }}"
  loop: "{{ validation_check.results }}"
  when: validation_check.results is defined
```

## Integration Examples

### 1. Web Server Configuration (Nginx)

```yaml
- name: Update Nginx SSL configuration
  template:
    src: nginx-ssl.conf.j2
    dest: /etc/nginx/sites-available/{{ domain }}.conf
  vars:
    ssl_certificate: "{{ certificate_path }}"
    ssl_certificate_key: "{{ private_key_path }}"
  notify: reload nginx
  when: cert_result.changed

- name: Reload Nginx
  service:
    name: nginx
    state: reloaded
  listen: reload nginx
```

### 2. Automated Renewal Cron Job

```yaml
- name: Create certificate renewal script
  template:
    src: renew-certs.yml.j2
    dest: /opt/ansible/renew-certs.yml
    mode: '0755'

- name: Schedule certificate renewal
  cron:
    name: "ZeroSSL certificate renewal"
    minute: "0"
    hour: "2"
    day: "1"
    job: "ansible-playbook /opt/ansible/renew-certs.yml"
```

## Testing and Validation

### 1. Certificate Verification

```bash
# Verify certificate after deployment
openssl x509 -in /etc/ssl/certs/example.com.crt -text -noout
openssl verify -CAfile /etc/ssl/certs/ca-bundle.crt /etc/ssl/certs/example.com.crt
```

### 2. SSL/TLS Testing

```bash
# Test SSL configuration
curl -I https://example.com
openssl s_client -connect example.com:443 -servername example.com
```

This quickstart guide provides the foundation for using the Ansible ZeroSSL plugin in production environments with proper security practices and error handling.
