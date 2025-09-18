# -*- coding: utf-8 -*-
"""
ZeroSSL API Response Fixtures.

Mock responses for ZeroSSL API endpoints used in testing.
"""

import json
from datetime import datetime, timedelta


# Mock Certificate Responses
CERTIFICATE_CREATED_RESPONSE = {
    "id": "cert-123456789",
    "type": "90-day",
    "common_name": "example.com",
    "additional_domains": "www.example.com,api.example.com",
    "created": "2025-01-15 10:30:00",
    "expires": "2025-04-15 10:30:00",
    "status": "draft",
    "validation_completed": False,
    "validation": {
        "email_validation": {},
        "other_methods": {
            "example.com": {
                "file_validation_url_http": "http://example.com/.well-known/pki-validation/validation-file.txt",
                "file_validation_url_https": "https://example.com/.well-known/pki-validation/validation-file.txt",
                "file_validation_content": ["content-hash-123", "domain-validation-content"],
                "cname_validation_p1": "_validation-hash",
                "cname_validation_p2": "validation.zerossl.com"
            },
            "www.example.com": {
                "file_validation_url_http": "http://www.example.com/.well-known/pki-validation/validation-file2.txt",
                "file_validation_url_https": "https://www.example.com/.well-known/pki-validation/validation-file2.txt",
                "file_validation_content": ["content-hash-456", "domain-validation-content-2"],
                "cname_validation_p1": "_validation-hash-2",
                "cname_validation_p2": "validation.zerossl.com"
            }
        }
    }
}

CERTIFICATE_PENDING_RESPONSE = {
    "id": "cert-123456789",
    "type": "90-day",
    "common_name": "example.com",
    "additional_domains": "www.example.com,api.example.com",
    "created": "2025-01-15 10:30:00",
    "expires": "2025-04-15 10:30:00",
    "status": "pending_validation",
    "validation_completed": False,
    "validation_type": "HTTP_CSR_HASH"
}

CERTIFICATE_ISSUED_RESPONSE = {
    "id": "cert-123456789",
    "type": "90-day",
    "common_name": "example.com",
    "additional_domains": "www.example.com,api.example.com",
    "created": "2025-01-15 10:30:00",
    "expires": "2025-04-15 10:30:00",
    "status": "issued",
    "validation_completed": True,
    "validation_type": "HTTP_CSR_HASH",
    "issued": "2025-01-15 11:45:00"
}

CERTIFICATE_EXPIRED_RESPONSE = {
    "id": "cert-987654321",
    "type": "90-day",
    "common_name": "expired.example.com",
    "additional_domains": "",
    "created": "2024-10-15 10:30:00",
    "expires": "2025-01-13 10:30:00",
    "status": "expired",
    "validation_completed": True,
    "validation_type": "HTTP_CSR_HASH"
}

# Mock Certificate List Response
CERTIFICATE_LIST_RESPONSE = {
    "total_count": 3,
    "result_count": 3,
    "page": 1,
    "limit": 25,
    "results": [
        CERTIFICATE_ISSUED_RESPONSE,
        CERTIFICATE_PENDING_RESPONSE,
        CERTIFICATE_EXPIRED_RESPONSE
    ]
}

# Mock Validation Response
VALIDATION_SUCCESS_RESPONSE = {
    "success": True,
    "validation_completed": True,
    "certificate_id": "cert-123456789"
}

VALIDATION_PENDING_RESPONSE = {
    "success": True,
    "validation_completed": False,
    "certificate_id": "cert-123456789",
    "validation_details": {
        "example.com": {
            "validation_status": "pending",
            "validation_method": "HTTP_CSR_HASH"
        }
    }
}

# Mock Error Responses
ERROR_INVALID_API_KEY = {
    "error": {
        "code": 10001,
        "type": "invalid_api_key",
        "message": "Invalid API key provided"
    }
}

ERROR_RATE_LIMIT = {
    "error": {
        "code": 429,
        "type": "rate_limit_exceeded",
        "message": "API rate limit exceeded. Please try again later."
    }
}

ERROR_CERTIFICATE_NOT_FOUND = {
    "error": {
        "code": 10404,
        "type": "certificate_not_found",
        "message": "Certificate with the specified ID was not found"
    }
}

ERROR_DOMAIN_VALIDATION_FAILED = {
    "error": {
        "code": 10301,
        "type": "domain_validation_failed",
        "message": "Domain validation failed for one or more domains"
    }
}

# Mock Certificate Files (PEM format)
MOCK_CERTIFICATE_PEM = """-----BEGIN CERTIFICATE-----
MIIFXjCCBEagAwIBAgISA1234567890abcdefghijklmnopqrstu...
[Certificate content would be here - truncated for brevity]
-----END CERTIFICATE-----"""

MOCK_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...
[Private key content would be here - truncated for brevity]
-----END PRIVATE KEY-----"""

MOCK_CA_BUNDLE_PEM = """-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhki...
[CA bundle content would be here - truncated for brevity]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFdDCCBFygAwIBAgIQJ2buVutJ846r13Ci/ITeIjANBgkqhki...
[Additional CA certificates would be here]
-----END CERTIFICATE-----"""

# Mock ZIP file content for certificate download
MOCK_CERTIFICATE_ZIP_FILES = {
    'certificate.crt': MOCK_CERTIFICATE_PEM,
    'private.key': MOCK_PRIVATE_KEY_PEM,
    'ca_bundle.crt': MOCK_CA_BUNDLE_PEM
}

# Mock CSR content
MOCK_CSR_PEM = """-----BEGIN CERTIFICATE REQUEST-----
MIICZjCCAU4CAQAwGTEXMBUGA1UEAwwOZXhhbXBsZS5jb20wggEi...
[CSR content would be here - truncated for brevity]
-----END CERTIFICATE REQUEST-----"""

# Helper functions for dynamic responses
def create_certificate_response(
    cert_id="cert-123456789",
    common_name="example.com",
    additional_domains="",
    status="draft",
    days_valid=90
):
    """Create a dynamic certificate response."""
    now = datetime.utcnow()
    expires = now + timedelta(days=days_valid)

    return {
        "id": cert_id,
        "type": f"{days_valid}-day",
        "common_name": common_name,
        "additional_domains": additional_domains,
        "created": now.strftime("%Y-%m-%d %H:%M:%S"),
        "expires": expires.strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "validation_completed": status == "issued",
        "validation_type": "HTTP_CSR_HASH"
    }

def create_validation_files_response(domains):
    """Create validation files for given domains."""
    validation_data = {}

    for i, domain in enumerate(domains, 1):
        validation_data[domain] = {
            "file_validation_url_http": f"http://{domain}/.well-known/pki-validation/validation-file{i}.txt",
            "file_validation_url_https": f"https://{domain}/.well-known/pki-validation/validation-file{i}.txt",
            "file_validation_content": [f"content-hash-{i}", f"domain-validation-content-{i}"],
            "cname_validation_p1": f"_validation-hash-{i}",
            "cname_validation_p2": "validation.zerossl.com"
        }

    return validation_data

def create_dns_records_response(domains):
    """Create DNS validation records for given domains."""
    dns_records = []

    for i, domain in enumerate(domains, 1):
        dns_records.append({
            "name": f"_acme-challenge.{domain}",
            "type": "TXT",
            "value": f"validation-token-{i}-{domain.replace('.', '-')}",
            "ttl": 300
        })

    return dns_records

# Rate limiting responses
RATE_LIMIT_HEADERS = {
    'X-RateLimit-Limit': '5000',
    'X-RateLimit-Remaining': '4999',
    'X-RateLimit-Reset': '1642678800'
}

RATE_LIMIT_EXCEEDED_HEADERS = {
    'X-RateLimit-Limit': '5000',
    'X-RateLimit-Remaining': '0',
    'X-RateLimit-Reset': '1642678800',
    'Retry-After': '3600'
}

# Test scenarios data
TEST_SCENARIOS = {
    'single_domain': {
        'domains': ['example.com'],
        'validation_method': 'HTTP_CSR_HASH'
    },
    'multi_domain': {
        'domains': ['example.com', 'www.example.com', 'api.example.com'],
        'validation_method': 'HTTP_CSR_HASH'
    },
    'wildcard_domain': {
        'domains': ['*.example.com'],
        'validation_method': 'DNS_CSR_HASH'
    },
    'mixed_domains': {
        'domains': ['example.com', '*.api.example.com', 'subdomain.example.com'],
        'validation_method': 'DNS_CSR_HASH'
    }
}

# Configuration test data
TEST_CONFIGURATIONS = {
    'minimal': {
        'api_key': 'test-api-key-123',
        'domains': ['example.com'],
        'state': 'present'
    },
    'complete': {
        'api_key': 'test-api-key-123',
        'domains': ['example.com', 'www.example.com'],
        'state': 'present',
        'validation_method': 'HTTP_CSR_HASH',
        'certificate_path': '/etc/ssl/certs/example.com.crt',
        'private_key_path': '/etc/ssl/private/example.com.key',
        'ca_bundle_path': '/etc/ssl/certs/example.com-ca.crt',
        'full_chain_path': '/etc/ssl/certs/example.com-fullchain.crt',
        'validity_days': 90,
        'renew_threshold_days': 30,
        'timeout': 30,
        'web_root': '/var/www/html'
    },
    'dns_validation': {
        'api_key': 'test-api-key-123',
        'domains': ['*.example.com'],
        'state': 'present',
        'validation_method': 'DNS_CSR_HASH',
        'certificate_path': '/etc/ssl/certs/wildcard.example.com.crt'
    }
}
