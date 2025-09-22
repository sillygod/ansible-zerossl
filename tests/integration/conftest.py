# -*- coding: utf-8 -*-
"""
Fixtures and configuration for integration tests.

These fixtures support real API testing with ZeroSSL.
"""

import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock


@pytest.fixture(scope="session")
def zerossl_api_key():
    """
    Real ZeroSSL API key from environment.

    Set ZEROSSL_API_KEY environment variable to run integration tests.
    """
    api_key = os.getenv("ZEROSSL_API_KEY")
    if not api_key:
        pytest.skip("ZEROSSL_API_KEY environment variable not set")
    return api_key


@pytest.fixture(scope="session")
def test_domains():
    """
    Test domains you control for validation.

    Set ZEROSSL_TEST_DOMAINS environment variable (comma-separated).
    Example: ZEROSSL_TEST_DOMAINS="test.example.com,api.example.com"
    """
    domains_str = os.getenv("ZEROSSL_TEST_DOMAINS", "")
    if not domains_str:
        pytest.skip("ZEROSSL_TEST_DOMAINS environment variable not set")

    domains = [d.strip() for d in domains_str.split(",") if d.strip()]
    if not domains:
        pytest.skip("No valid test domains found in ZEROSSL_TEST_DOMAINS")

    return domains


@pytest.fixture
def live_action_base():
    """Mock ActionBase for live testing."""
    action = Mock()
    action._task = Mock()
    action._task.args = {}
    action._task.action = 'zerossl_certificate'
    action._task.delegate_to = None
    action._task.async_val = 0
    action._execute_module = Mock()
    action._display = Mock()
    return action


@pytest.fixture
def live_task_vars():
    """Real task variables for live testing."""
    return {
        'ansible_host': 'localhost',
        'ansible_user': os.getenv('USER', 'testuser'),
        'inventory_hostname': 'test-host'
    }


@pytest.fixture
def temp_cert_directory():
    """Temporary directory for certificate files during live tests."""
    csr_path =  os.getenv("ZEROSSL_CERT_CSR_DIR", "")
    if csr_path:
        cert_dir =  Path(csr_path) / "certificates"
        cert_dir.mkdir(exist_ok=True)
        yield cert_dir
    else:
        with tempfile.TemporaryDirectory(prefix="zerossl_live_test_") as tmpdir:
            cert_dir = Path(tmpdir) / "certificates"
            cert_dir.mkdir(exist_ok=True)
            yield cert_dir


@pytest.fixture
def cleanup_certificates():
    """
    Fixture to help cleanup test certificates after live tests.

    Yields a list that test functions can append certificate IDs to.
    The fixture will attempt to clean them up after the test.
    """
    certificate_ids = []
    yield certificate_ids

    # Cleanup logic would go here
    # Note: ZeroSSL API doesn't always allow deletion, so this might just log
    if certificate_ids:
        print(f"Test created certificates: {certificate_ids}")
        print("Manual cleanup may be required via ZeroSSL dashboard")


@pytest.fixture(autouse=True)
def skip_if_no_live_env():
    """
    Automatically skip integration tests if live environment is not configured.

    This runs before every integration test to check if the environment
    is properly configured for live testing.
    """
    if not os.getenv("ZEROSSL_API_KEY"):
        pytest.skip("Live integration tests require ZEROSSL_API_KEY environment variable")

    if not os.getenv("ZEROSSL_TEST_DOMAINS"):
        pytest.skip("Live integration tests require ZEROSSL_TEST_DOMAINS environment variable")


@pytest.fixture
def integration_test_config():
    """Configuration for integration tests."""
    return {
        "timeout": 300,  # 5 minutes for certificate operations
        "max_retries": 3,
        "retry_delay": 5,  # seconds
        "validation_timeout": 180,  # 3 minutes for domain validation
        "enable_cleanup": os.getenv("ZEROSSL_CLEANUP_AFTER_TESTS", "true").lower() == "true"
    }
