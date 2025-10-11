# -*- coding: utf-8 -*-
"""
API Response Fixtures for improved test design.

This module imports realistic ZeroSSL API responses from the existing
zerossl_responses.py file to maintain consistency with established patterns.
"""

# Import existing realistic API responses
from ..zerossl_responses import (
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
    RATE_LIMIT_HEADERS,
    RATE_LIMIT_EXCEEDED_HEADERS,
    create_certificate_response,
    create_validation_files_response,
    create_dns_records_response,
    TEST_SCENARIOS,
    TEST_CONFIGURATIONS,
)

# Organize responses for improved test design patterns
API_RESPONSES = {
    "create_certificate_success": CERTIFICATE_CREATED_RESPONSE,
    "validation_pending": CERTIFICATE_PENDING_RESPONSE,
    "certificate_issued": CERTIFICATE_ISSUED_RESPONSE,
    "certificate_expired": CERTIFICATE_EXPIRED_RESPONSE,
    "rate_limit_error": ERROR_RATE_LIMIT,
    "validation_error": ERROR_DOMAIN_VALIDATION_FAILED,
    "invalid_api_key": ERROR_INVALID_API_KEY,
    "certificate_not_found": ERROR_CERTIFICATE_NOT_FOUND,
    "certificate_list": CERTIFICATE_LIST_RESPONSE,
    "validation_success": VALIDATION_SUCCESS_RESPONSE,
    "validation_pending_details": VALIDATION_PENDING_RESPONSE,
}


# Helper functions for dynamic test data
def get_response(response_type, **kwargs):
    """Get a response by type with optional customization."""
    if response_type in API_RESPONSES:
        response = API_RESPONSES[response_type].copy()
        response.update(kwargs)
        return response
    raise ValueError(f"Unknown response type: {response_type}")


def get_test_scenario(scenario_name):
    """Get test scenario configuration."""
    return TEST_SCENARIOS.get(scenario_name, {})


def get_test_configuration(config_name):
    """Get test configuration."""
    return TEST_CONFIGURATIONS.get(config_name, {})
