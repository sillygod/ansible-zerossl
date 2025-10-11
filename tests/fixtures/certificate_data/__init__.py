# -*- coding: utf-8 -*-
"""
Certificate Data Fixtures for improved test design.

This module imports realistic certificate PEM data from the existing
zerossl_responses.py file to maintain consistency with established patterns.
"""

# Import existing realistic certificate data
from ..zerossl_responses import (
    MOCK_CERTIFICATE_PEM,
    MOCK_PRIVATE_KEY_PEM,
    MOCK_CA_BUNDLE_PEM,
    MOCK_CSR_PEM,
    MOCK_CERTIFICATE_ZIP_FILES,
)

# Organize certificate data for improved test design patterns
CERTIFICATE_DATA = {
    "sample_certificate.pem": MOCK_CERTIFICATE_PEM,
    "sample_private_key.pem": MOCK_PRIVATE_KEY_PEM,
    "sample_ca_bundle.pem": MOCK_CA_BUNDLE_PEM,
    "sample_csr.pem": MOCK_CSR_PEM,
}

# Certificate bundle for testing
CERTIFICATE_BUNDLE = {
    "certificate": MOCK_CERTIFICATE_PEM,
    "private_key": MOCK_PRIVATE_KEY_PEM,
    "ca_bundle": MOCK_CA_BUNDLE_PEM,
    "full_chain": MOCK_CERTIFICATE_PEM + "\n" + MOCK_CA_BUNDLE_PEM,
}

# ZIP file structure for download testing
ZIP_FILE_CONTENTS = MOCK_CERTIFICATE_ZIP_FILES


def get_certificate_data(data_type):
    """Get certificate data by type."""
    if data_type in CERTIFICATE_DATA:
        return CERTIFICATE_DATA[data_type]
    raise ValueError(f"Unknown certificate data type: {data_type}")


def get_certificate_bundle():
    """Get complete certificate bundle."""
    return CERTIFICATE_BUNDLE.copy()


def get_zip_contents():
    """Get ZIP file contents for testing certificate downloads."""
    return ZIP_FILE_CONTENTS.copy()
