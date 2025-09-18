# -*- coding: utf-8 -*-
"""
ZeroSSL Test Fixtures Package.

This package contains comprehensive test fixtures for the ZeroSSL Ansible plugin,
including mock API responses, sample certificates, and test helper utilities.
"""

from .zerossl_responses import (
    CERTIFICATE_CREATED_RESPONSE,
    CERTIFICATE_PENDING_RESPONSE,
    CERTIFICATE_ISSUED_RESPONSE,
    CERTIFICATE_EXPIRED_RESPONSE,
    CERTIFICATE_LIST_RESPONSE,
    VALIDATION_SUCCESS_RESPONSE,
    VALIDATION_PENDING_RESPONSE,
    ERROR_INVALID_API_KEY,
    ERROR_RATE_LIMIT,
    ERROR_CERTIFICATE_NOT_FOUND,
    ERROR_DOMAIN_VALIDATION_FAILED,
    MOCK_CERTIFICATE_PEM,
    MOCK_PRIVATE_KEY_PEM,
    MOCK_CA_BUNDLE_PEM,
    MOCK_CSR_PEM,
    TEST_SCENARIOS,
    TEST_CONFIGURATIONS,
    create_certificate_response,
    create_validation_files_response,
    create_dns_records_response
)

from .mock_helpers import (
    MockResponse,
    MockZeroSSLAPIClient,
    MockCertificateManager,
    MockValidationHandler,
    create_mock_session_with_responses,
    create_mock_certificate_zip,
    create_test_file_structure,
    assert_file_content,
    assert_file_permissions
)

from .sample_certificates import (
    SAMPLE_CSR,
    SAMPLE_SINGLE_DOMAIN_CERT,
    SAMPLE_MULTI_DOMAIN_CERT,
    SAMPLE_WILDCARD_CERT,
    SAMPLE_PRIVATE_KEY,
    SAMPLE_CA_BUNDLE,
    TEST_CERTIFICATE_CHAINS,
    SAMPLE_VALIDATION_FILES,
    SAMPLE_DNS_RECORDS,
    ERROR_SCENARIOS,
    PERFORMANCE_TEST_DATA,
    FILE_PERMISSION_TESTS
)

__all__ = [
    # Response fixtures
    'CERTIFICATE_CREATED_RESPONSE',
    'CERTIFICATE_PENDING_RESPONSE',
    'CERTIFICATE_ISSUED_RESPONSE',
    'CERTIFICATE_EXPIRED_RESPONSE',
    'CERTIFICATE_LIST_RESPONSE',
    'VALIDATION_SUCCESS_RESPONSE',
    'VALIDATION_PENDING_RESPONSE',
    'ERROR_INVALID_API_KEY',
    'ERROR_RATE_LIMIT',
    'ERROR_CERTIFICATE_NOT_FOUND',
    'ERROR_DOMAIN_VALIDATION_FAILED',
    'MOCK_CERTIFICATE_PEM',
    'MOCK_PRIVATE_KEY_PEM',
    'MOCK_CA_BUNDLE_PEM',
    'MOCK_CSR_PEM',
    'TEST_SCENARIOS',
    'TEST_CONFIGURATIONS',
    'create_certificate_response',
    'create_validation_files_response',
    'create_dns_records_response',

    # Mock helpers
    'MockResponse',
    'MockZeroSSLAPIClient',
    'MockCertificateManager',
    'MockValidationHandler',
    'create_mock_session_with_responses',
    'create_mock_certificate_zip',
    'create_test_file_structure',
    'assert_file_content',
    'assert_file_permissions',

    # Sample certificates
    'SAMPLE_CSR',
    'SAMPLE_SINGLE_DOMAIN_CERT',
    'SAMPLE_MULTI_DOMAIN_CERT',
    'SAMPLE_WILDCARD_CERT',
    'SAMPLE_PRIVATE_KEY',
    'SAMPLE_CA_BUNDLE',
    'TEST_CERTIFICATE_CHAINS',
    'SAMPLE_VALIDATION_FILES',
    'SAMPLE_DNS_RECORDS',
    'ERROR_SCENARIOS',
    'PERFORMANCE_TEST_DATA',
    'FILE_PERMISSION_TESTS'
]
