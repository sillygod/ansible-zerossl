# -*- coding: utf-8 -*-
"""
Shared pytest fixtures for Ansible ZeroSSL plugin tests.
"""

import os
import pytest
import tempfile
import json
from unittest.mock import Mock, MagicMock
from pathlib import Path

# Add module_utils to Python path for testing
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture
def mock_ansible_module():
    """Mock AnsibleModule for testing."""
    module = Mock()
    module.params = {}
    module.fail_json = Mock(side_effect=Exception("fail_json called"))
    module.exit_json = Mock()
    module.warn = Mock()
    module.debug = Mock()
    return module


@pytest.fixture
def mock_action_base():
    """Mock ActionBase for action plugin testing."""
    action = Mock()
    action._task = Mock()
    action._task.args = {}
    action._task.action = 'zerossl_certificate'
    action._task.delegate_to = None
    action._task.async_val = 0  # Not async
    action._execute_module = Mock()
    action._display = Mock()
    return action


@pytest.fixture
def sample_api_key():
    """Sample ZeroSSL API key for testing."""
    return "zerossl_test_api_key_12345"


@pytest.fixture
def sample_domains():
    """Sample domain list for testing."""
    return ["example.com", "www.example.com"]


@pytest.fixture
def sample_csr():
    """Sample Certificate Signing Request content."""
    return """-----BEGIN CERTIFICATE REQUEST-----
MIIBWjCB5AIBADAVMRMwEQYDVQQDDApkb21haW4uY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQC3U8+3lGpQ+5q5C5l3qDjOQcGQPjp1CZqV2X/Vr8VKcX1
XjGpQnQX8V3lGpQ+5q5C5l3qDjOQcGQPjp1CZqV2X/Vr8VKcX1XjGpQnQX8V3l
GpQ+5q5C5l3qDjOQcGQPjp1CZqV2X/Vr8VKcX1XjGpQnQX8V3lGpQ+5q5C5l3q
DjOQcGQPjp1CZqV2X/VqgIwIBAAoGBALdTz7eUalD7mrkLmXeoOM5BwZA+OnUJ
mpXZf9WvxUpxfVeMalCdBfxXeUalD7mrkLmXeoOM5BwZA+OnUJmpXZf9WvxUpx
fVeMalCdBfxXeUalD7mrkLmXeoOM5BwZA+OnUJmpXZf9WvxUpxfVeMalCdBfxX
eUalD7mrkLmXeoOM5BwZA+OnUJmpXZf9Wq
-----END CERTIFICATE REQUEST-----"""


@pytest.fixture
def sample_certificate_response():
    """Sample ZeroSSL API certificate response."""
    return {
        "id": "test_cert_123456789",
        "common_name": "example.com",
        "additional_domains": "www.example.com",
        "status": "draft",
        "created": "2025-09-17 12:00:00",
        "expires": "2025-12-16 12:00:00",
        "validation": {
            "email_validation": {},
            "other_methods": {
                "example.com": {
                    "file_validation_url_http": "http://example.com/.well-known/pki-validation/test123.txt",
                    "file_validation_content": "test_validation_content_123"
                },
                "www.example.com": {
                    "file_validation_url_http": "http://www.example.com/.well-known/pki-validation/test456.txt",
                    "file_validation_content": "test_validation_content_456"
                }
            }
        }
    }


@pytest.fixture
def sample_certificate_bundle():
    """Sample certificate bundle content."""
    return {
        "certificate": """-----BEGIN CERTIFICATE-----
MIIC5TCCAc2gAwIBAgIJAKZZQQMNPjONMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0yNTA5MTcxMjAwMDBaFw0yNTEyMTYxMjAwMDBaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALdTz7eUalD7mrkLmXeoOM5BwZA+OnUJmpXZf9WvxUpxfVeMalCdBfxXeUal
-----END CERTIFICATE-----""",
        "private_key": """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3U8+3lGpQ+5q5
C5l3qDjOQcGQPjp1CZqV2X/Vr8VKcX1XjGpQnQX8V3lGpQ+5q5C5l3qDjOQcGQP
jp1CZqV2X/Vr8VKcX1XjGpQnQX8V3lGpQ+5q5C5l3qDjOQcGQPjp1CZqV2X/Vr8
-----END PRIVATE KEY-----""",
        "ca_bundle": """-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDE4MDI0OFoXDTIxMDkzMDE4MDI0OFow
-----END CERTIFICATE-----"""
    }


@pytest.fixture
def temp_directory():
    """Temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def mock_task_vars():
    """Mock task variables for Ansible testing."""
    return {
        'ansible_host': 'localhost',
        'ansible_user': 'testuser',
        'inventory_hostname': 'test-host'
    }


@pytest.fixture
def mock_zerossl_api_responses():
    """Mock responses for ZeroSSL API calls."""
    return {
        'create_certificate': {
            'status_code': 200,
            'content': json.dumps({
                "id": "test_cert_123456789",
                "status": "draft",
                "validation": {
                    "other_methods": {
                        "example.com": {
                            "file_validation_url_http": "http://example.com/.well-known/pki-validation/test123.txt",
                            "file_validation_content": "test_validation_content_123"
                        }
                    }
                }
            })
        },
        'validate_certificate': {
            'status_code': 200,
            'content': json.dumps({
                "success": True,
                "validation_completed": True
            })
        },
        'get_certificate': {
            'status_code': 200,
            'content': json.dumps({
                "id": "test_cert_123456789",
                "status": "issued",
                "expires": "2025-12-16 12:00:00"
            })
        }
    }


@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    """Setup test environment variables."""
    # Ensure test environment is clean
    test_env_vars = {
        'ANSIBLE_HOST_KEY_CHECKING': 'False',
        'ANSIBLE_RETRY_FILES_ENABLED': 'False',
        'ANSIBLE_PIPELINING': 'True'
    }

    for key, value in test_env_vars.items():
        monkeypatch.setenv(key, value)


# Pytest plugins for Ansible-specific testing
pytest_plugins = [
    'pytest_ansible',
]


def pytest_configure(config):
    """Configure pytest for Ansible testing."""
    # Add custom markers
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "component: Component tests with mocked dependencies")
    config.addinivalue_line("markers", "integration: Real integration tests with external APIs")
    config.addinivalue_line("markers", "contract: Contract tests")
    config.addinivalue_line("markers", "slow: Slow tests")
    config.addinivalue_line("markers", "network: Network tests")
    config.addinivalue_line("markers", "live: Live tests requiring real API keys")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Auto-mark tests based on path
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "component" in str(item.fspath):
            item.add_marker(pytest.mark.component)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
            item.add_marker(pytest.mark.live)  # Integration tests are live by default
        elif "contract" in str(item.fspath):
            item.add_marker(pytest.mark.contract)

        # Mark network tests
        if "api" in item.name.lower() or "network" in item.name.lower():
            item.add_marker(pytest.mark.network)

        # Mark live tests that require real API
        if "live" in item.name.lower() or "real" in item.name.lower():
            item.add_marker(pytest.mark.live)
