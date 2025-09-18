# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Ansible ZeroSSL Plugin Contributors
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ZeroSSL module utilities for Ansible certificate management.

This package provides modular components for managing SSL certificates
through the ZeroSSL API, including:
- API client with rate limiting and retry logic
- Certificate lifecycle management
- Domain validation handlers (HTTP-01, DNS-01)
- Configuration validation and error handling
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from .models import (
    Certificate,
    CertificateBundle,
    DomainValidation,
    APICredentials,
    CertificateStatus,
    ValidationMethod,
    ValidationStatus,
    OperationState
)

from .exceptions import (
    ZeroSSLException,
    ZeroSSLHTTPError,
    ZeroSSLValidationError,
    ZeroSSLCertificateError,
    ZeroSSLConfigurationError,
    ZeroSSLRateLimitError,
    ZeroSSLTimeoutError,
    ZeroSSLFileSystemError,
    ZeroSSLSecurityError,
    format_exception_for_ansible,
    is_retryable_error,
    get_retry_delay
)

from .api_client import ZeroSSLAPIClient
from .certificate_manager import CertificateManager
from .validation_handler import ValidationHandler
from .config_validator import ConfigValidator

from .utils import (
    validate_domain,
    validate_domains,
    validate_api_key,
    validate_file_path,
    is_wildcard_domain,
    extract_base_domain,
    domains_overlap,
    check_domain_dns_resolution,
    check_domain_http_accessibility,
    parse_validation_url,
    generate_csr,
    normalize_certificate_content,
    extract_certificate_info,
    create_file_with_permissions
)

__version__ = "1.0.0"
__author__ = "Ansible ZeroSSL Plugin Contributors"

__all__ = [
    # Models
    'Certificate',
    'CertificateBundle',
    'DomainValidation',
    'APICredentials',
    'CertificateStatus',
    'ValidationMethod',
    'ValidationStatus',
    'OperationState',

    # Exceptions
    'ZeroSSLException',
    'ZeroSSLHTTPError',
    'ZeroSSLValidationError',
    'ZeroSSLCertificateError',
    'ZeroSSLConfigurationError',
    'ZeroSSLRateLimitError',
    'ZeroSSLTimeoutError',
    'ZeroSSLFileSystemError',
    'ZeroSSLSecurityError',
    'format_exception_for_ansible',
    'is_retryable_error',
    'get_retry_delay',

    # Core Classes
    'ZeroSSLAPIClient',
    'CertificateManager',
    'ValidationHandler',
    'ConfigValidator',

    # Utility Functions
    'validate_domain',
    'validate_domains',
    'validate_api_key',
    'validate_file_path',
    'is_wildcard_domain',
    'extract_base_domain',
    'domains_overlap',
    'check_domain_dns_resolution',
    'check_domain_http_accessibility',
    'parse_validation_url',
    'generate_csr',
    'normalize_certificate_content',
    'extract_certificate_info',
    'create_file_with_permissions'
]
