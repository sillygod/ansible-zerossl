# -*- coding: utf-8 -*-
"""
Sample Certificate Data for Testing.

Real-world like certificate data for comprehensive testing scenarios.
"""

# Sample CSR for testing
SAMPLE_CSR = """-----BEGIN CERTIFICATE REQUEST-----
MIICZjCCAU4CAQAwGTEXMBUGA1UEAwwOZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC7S0ZyKKe8PO1234567890abcdefghijklmnop
qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqr
stuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstu
vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwx
yzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzA
BCDEFGHIJKLMNOPQRSTUVWXYZwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAGH
I1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12
34567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
-----END CERTIFICATE REQUEST-----"""

# Sample certificate for single domain
SAMPLE_SINGLE_DOMAIN_CERT = """-----BEGIN CERTIFICATE-----
MIIFXjCCBEagAwIBAgISA3456789012345678901234567890123456789012345
6789012345678901234567890123456789012345678901234567890123456789
0123456789012345678901234567890123456789012345678901234567890123
4567890123456789012345678901234567890123456789012345678901234567
8901234567890123456789012345678901234567890123456789012345678901
2345678901234567890123456789012345678901234567890123456789012345
6789012345678901234567890123456789012345678901234567890123456789
0123456789012345678901234567890123456789012345678901234567890123
4567890123456789012345678901234567890123456789012345678901234567
8901234567890123456789012345678901234567890123456789012345678901
2345678901234567890123456789012345678901234567890123456789012345
6789012345678901234567890123456789012345678901234567890123456789
0123456789012345678901234567890123456789012345678901234567890123
4567890123456789012345678901234567890123456789012345678901234567
8901234567890123456789012345678901234567890123456789012345678901
234567890123456789
-----END CERTIFICATE-----"""

# Sample multi-domain (SAN) certificate
SAMPLE_MULTI_DOMAIN_CERT = """-----BEGIN CERTIFICATE-----
MIIGXjCCBUagAwIBAgISA7890123456789012345678901234567890123456789
0123456789012345678901234567890123456789012345678901234567890123
4567890123456789012345678901234567890123456789012345678901234567
8901234567890123456789012345678901234567890123456789012345678901
2345678901234567890123456789012345678901234567890123456789012345
6789012345678901234567890123456789012345678901234567890123456789
0123456789012345678901234567890123456789012345678901234567890123
4567890123456789012345678901234567890123456789012345678901234567
8901234567890123456789012345678901234567890123456789012345678901
2345678901234567890123456789012345678901234567890123456789012345
6789012345678901234567890123456789012345678901234567890123456789
0123456789012345678901234567890123456789012345678901234567890123
4567890123456789012345678901234567890123456789012345678901234567
8901234567890123456789012345678901234567890123456789012345678901
2345678901234567890123456789012345678901234567890123456789012345
67890123456789012345678901234567890123456789
-----END CERTIFICATE-----"""

# Sample wildcard certificate
SAMPLE_WILDCARD_CERT = """-----BEGIN CERTIFICATE-----
MIIGYjCCBUqgAwIBAgISA9012345678901234567890123456789012345678901
2345678901234567890123456789012345678901234567890123456789012345
6789012345678901234567890123456789012345678901234567890123456789
0123456789012345678901234567890123456789012345678901234567890123
4567890123456789012345678901234567890123456789012345678901234567
8901234567890123456789012345678901234567890123456789012345678901
2345678901234567890123456789012345678901234567890123456789012345
6789012345678901234567890123456789012345678901234567890123456789
0123456789012345678901234567890123456789012345678901234567890123
4567890123456789012345678901234567890123456789012345678901234567
8901234567890123456789012345678901234567890123456789012345678901
2345678901234567890123456789012345678901234567890123456789012345
6789012345678901234567890123456789012345678901234567890123456789
0123456789012345678901234567890123456789012345678901234567890123
4567890123456789012345678901234567890123456789012345678901234567
8901234567890123456789012345678901234567890
-----END CERTIFICATE-----"""

# Sample private key (for testing only - not real)
SAMPLE_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7S0ZyKKe8PO12
34567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234
567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456
7890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345678
90abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZwIDAQABAoIBAG
LowNO1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW
XYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY
Z1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1
234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123
4567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345
67890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567
890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789
0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
-----END PRIVATE KEY-----"""

# Sample CA bundle with multiple certificates
SAMPLE_CA_BUNDLE = """-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA
hMTEwLwYDVQQDEyhGYWtlIExFIEludGVybWVkaWF0ZSBYMSAoU1RBR0lORyBF
TlYpMEAGA1UEChMZKFNUQUdJTkcpIEZha2UgTEUgSW5jOjAeFw0yNTAxMTUwOT
IwNDBaFw0yNTEwMTQwOTIwNDBaMBYxFDASBgNVBAMTC2V4YW1wbGUuY29tMII
BIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt0tGciinvDztdbA8zLu
6TqLJ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST
UVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS
TUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR
STUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ
RSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP
QRSTUVWXYZwIDAQABo4IDeDCCA3QwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQ
WMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQ
WBBSKdH+vhfGydGxVy5234567890abcdefghijklmnopqr=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFdDCCBFygAwIBAgIQJ2buVutJ846r13Ci/ITeIjANBgkqhkiG9w0BAQsFAD
AhMTEwLwYDVQQDEyhGYWtlIExFIFJvb3QgWDEgKFNUQUdJTkcgRU5WKTEhMB8
GA1UEChMYKFNUQUdJTkcpIEZha2UgTEUgSW5jOjAeFw0yNTAxMDExMDAwMDBa
Fw0zNTEyMzEyMzU5NTlaMCExMTAvBgNVBAMTKEZha2UgTEUgSW50ZXJtZWRp
YXRlIFgxIChTVEFHSU5HIEVOVikxITAfBgNVBAoTGChTVEFHSU5HKSBGYWtl
IExFIEluYzowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYwJtR
JWLz12345678901234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ
KLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH
IJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEF
GHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCD
EFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzAB
CDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz
ABC==
-----END CERTIFICATE-----"""

# Test certificate chains for different scenarios
TEST_CERTIFICATE_CHAINS = {
    'single_domain': {
        'certificate': SAMPLE_SINGLE_DOMAIN_CERT,
        'private_key': SAMPLE_PRIVATE_KEY,
        'ca_bundle': SAMPLE_CA_BUNDLE,
        'domains': ['example.com'],
        'common_name': 'example.com'
    },
    'multi_domain': {
        'certificate': SAMPLE_MULTI_DOMAIN_CERT,
        'private_key': SAMPLE_PRIVATE_KEY,
        'ca_bundle': SAMPLE_CA_BUNDLE,
        'domains': ['example.com', 'www.example.com', 'api.example.com'],
        'common_name': 'example.com'
    },
    'wildcard': {
        'certificate': SAMPLE_WILDCARD_CERT,
        'private_key': SAMPLE_PRIVATE_KEY,
        'ca_bundle': SAMPLE_CA_BUNDLE,
        'domains': ['*.example.com'],
        'common_name': '*.example.com'
    }
}

# Validation file content samples
SAMPLE_VALIDATION_FILES = {
    'example.com': {
        'filename': 'validation-example-com.txt',
        'content': 'example-com-validation-hash-1234567890abcdef',
        'url_path': '/.well-known/pki-validation/validation-example-com.txt'
    },
    'www.example.com': {
        'filename': 'validation-www-example-com.txt',
        'content': 'www-example-com-validation-hash-abcdef1234567890',
        'url_path': '/.well-known/pki-validation/validation-www-example-com.txt'
    },
    'api.example.com': {
        'filename': 'validation-api-example-com.txt',
        'content': 'api-example-com-validation-hash-567890abcdef1234',
        'url_path': '/.well-known/pki-validation/validation-api-example-com.txt'
    }
}

# DNS validation records samples
SAMPLE_DNS_RECORDS = {
    'example.com': [
        {
            'name': '_acme-challenge.example.com',
            'type': 'TXT',
            'value': 'dns-validation-token-example-com-1234567890abcdef',
            'ttl': 300
        }
    ],
    '*.example.com': [
        {
            'name': '_acme-challenge.example.com',
            'type': 'TXT',
            'value': 'dns-validation-token-wildcard-example-com-abcdef1234567890',
            'ttl': 300
        }
    ],
    'multi_domain': [
        {
            'name': '_acme-challenge.example.com',
            'type': 'TXT',
            'value': 'dns-validation-token-example-com-1234567890abcdef',
            'ttl': 300
        },
        {
            'name': '_acme-challenge.www.example.com',
            'type': 'TXT',
            'value': 'dns-validation-token-www-example-com-abcdef1234567890',
            'ttl': 300
        },
        {
            'name': '_acme-challenge.api.example.com',
            'type': 'TXT',
            'value': 'dns-validation-token-api-example-com-567890abcdef1234',
            'ttl': 300
        }
    ]
}

# Error scenarios for testing
ERROR_SCENARIOS = {
    'invalid_domain': {
        'domains': ['invalid..domain.com'],
        'expected_error': 'Invalid domain name'
    },
    'missing_csr': {
        'domains': ['example.com'],
        'csr': '',
        'expected_error': 'CSR content is required'
    },
    'invalid_validation_method': {
        'domains': ['example.com'],
        'validation_method': 'INVALID_METHOD',
        'expected_error': 'validation_method must be'
    },
    'wildcard_with_http': {
        'domains': ['*.example.com'],
        'validation_method': 'HTTP_CSR_HASH',
        'expected_error': 'Wildcard domains require DNS validation'
    }
}

# Performance test data
PERFORMANCE_TEST_DATA = {
    'large_domain_list': [f'subdomain{i}.example.com' for i in range(100)],
    'concurrent_operations': [
        {'domains': [f'test{i}.example.com'], 'validation_method': 'HTTP_CSR_HASH'}
        for i in range(25)  # Support up to 25 concurrent operations
    ],
    'rapid_api_calls': [
        {'action': 'create', 'delay': 0.1},
        {'action': 'status', 'delay': 0.1},
        {'action': 'validate', 'delay': 0.1},
        {'action': 'download', 'delay': 0.1}
    ] * 20  # 80 rapid API calls
}

# File permission test cases
FILE_PERMISSION_TESTS = {
    'certificate': {
        'default_mode': 0o644,
        'secure_mode': 0o600,
        'public_readable': True
    },
    'private_key': {
        'default_mode': 0o600,
        'secure_mode': 0o600,
        'public_readable': False
    },
    'ca_bundle': {
        'default_mode': 0o644,
        'secure_mode': 0o600,
        'public_readable': True
    }
}
