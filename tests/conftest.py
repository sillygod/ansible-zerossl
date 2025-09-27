# -*- coding: utf-8 -*-
"""
Shared pytest fixtures for Ansible ZeroSSL plugin tests.

This module provides improved fixtures for HTTP boundary mocking and realistic test data.
Following the improved test design patterns:
- Mock only at HTTP/filesystem boundaries
- Use realistic ZeroSSL API response data
- Support parallel test execution
- Enable performance and coverage measurement
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
    # Common certificate content for testing
    certificate_content = """-----BEGIN CERTIFICATE-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDGV4YW1wbGUuY29tMIIB
-----END CERTIFICATE-----"""

    return {
        # Basic API responses
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
        },

        # Extended responses for component tests
        'list_certificates_empty': {
            "total_count": 0,
            "result_count": 0,
            "page": 1,
            "limit": 25,
            "results": []
        },
        'create_certificate_success': {
            'id': 'test_cert_success_123',
            'status': 'draft',
            'validation': {
                'other_methods': {
                    'example.com': {
                        'file_validation_url_http': 'http://example.com/.well-known/pki-validation/test.txt',
                        'file_validation_content': 'validation_content'
                    }
                }
            }
        },
        'validation_success': {
            'validation_completed': True
        },
        'certificate_download': {
            'certificate.crt': certificate_content
        },
        'list_certificates_with_valid_cert': {
            "total_count": 1,
            "result_count": 1,
            "page": 1,
            "limit": 25,
            "results": [{
                'id': 'valid_cert_123',
                'type': '90-day',
                'status': 'issued',
                'common_name': 'example.com',
                'additional_domains': 'www.example.com',
                'created': '2025-09-17 12:00:00',
                'expires': '2026-12-16 12:00:00',
                'validation_completed': True,
                'validation_type': 'HTTP_CSR_HASH',
                'domains': ['example.com', 'www.example.com']
            }]
        },
        'list_certificates_with_expiring_cert': {
            "total_count": 1,
            "result_count": 1,
            "page": 1,
            "limit": 25,
            "results": [{
                'id': 'expiring_cert_123',
                'type': '90-day',
                'status': 'issued',
                'common_name': 'example.com',
                'additional_domains': 'www.example.com',
                'created': '2025-07-02 12:00:00',
                'expires': '2025-10-01 12:00:00',  # Soon expiring
                'validation_completed': True,
                'validation_type': 'HTTP_CSR_HASH',
                'domains': ['example.com', 'www.example.com']
            }]
        },

        # Error responses
        'auth_error': {
            'error': {
                'code': 101,
                'type': 'invalid_access_key',
                'info': 'You have not supplied a valid API Access Key.'
            }
        },
        'rate_limit_error': {
            'error': {
                'code': 429,
                'type': 'rate_limit_exceeded',
                'info': 'Rate limit exceeded. Please try again later.'
            }
        },
        'validation_error': {
            'error': {
                'code': 400,
                'type': 'validation_failed',
                'info': 'Domain validation failed.'
            }
        },
        'download_error': {
            'error': {
                'code': 404,
                'type': 'certificate_not_found',
                'info': 'Certificate not found for download.'
            }
        },
        'list_certificates_error': {
            'error': {
                'code': 500,
                'type': 'internal_server_error',
                'info': 'Internal server error occurred.'
            }
        }
    }


@pytest.fixture
def zerossl_test_data():
    """Load realistic ZeroSSL API response data from fixtures."""
    fixtures_dir = Path(__file__).parent / "fixtures" / "api_responses"

    def load_json_fixture(filename):
        try:
            with open(fixtures_dir / filename, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Fallback to inline data if fixture files don't exist yet
            return {}

    return {
        "create_success": load_json_fixture("create_certificate_success.json"),
        "validation_pending": load_json_fixture("validation_pending.json"),
        "certificate_issued": load_json_fixture("certificate_issued.json"),
        "rate_limit_error": load_json_fixture("rate_limit_error.json"),
        "validation_error": load_json_fixture("validation_error.json"),
    }


@pytest.fixture
def mock_http_boundary(mocker, mock_zerossl_api_responses):
    """
    Mock only at HTTP boundary - no internal logic mocking.

    This fixture provides a sophisticated sequential HTTP mock that handles
    complete certificate workflows with realistic ZeroSSL API responses.
    """
    # Store endpoint mocks for accumulation (reset for each test)
    endpoint_mocks = {}

    # Define mock functions at the top level so they can be reused
    def create_mock_response(method, url):
        """Create mock response for given method and URL."""
        # Extract the path from the full URL
        if '?' in url:
            path = url.split('?')[0].replace('https://api.zerossl.com', '')
        else:
            path = url.replace('https://api.zerossl.com', '')

        # Check all registered endpoint mocks - prefer exact matches first, then longest matches
        matched_endpoint = None
        matched_config = None

        # First, look for exact matches
        if path in endpoint_mocks:
            matched_endpoint = path
            matched_config = endpoint_mocks[path]
        else:
            # Then look for prefix matches, preferring the longest match
            for mock_endpoint, mock_config in endpoint_mocks.items():
                if path.startswith(mock_endpoint) and (mock_endpoint != path):
                    if matched_endpoint is None or len(mock_endpoint) > len(matched_endpoint):
                        matched_endpoint = mock_endpoint
                        matched_config = mock_config

        if matched_endpoint:
            # Create mock response
            mock_response = Mock()
            mock_response.status_code = matched_config['status_code']

            # Set up headers (default + any custom headers)
            default_headers = {
                "X-Rate-Limit-Remaining": "999",
                "X-Rate-Limit-Limit": "1000",
                "Content-Type": "application/json"
            }
            if matched_config['headers']:
                default_headers.update(matched_config['headers'])
            mock_response.headers = default_headers

            mock_response.json.return_value = matched_config['response_data']
            import json
            mock_response.content = json.dumps(matched_config['response_data']).encode()
            return mock_response
        # Default response for unmatched endpoints
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.headers = {
            "X-Rate-Limit-Remaining": "999",
            "X-Rate-Limit-Limit": "1000",
            "Content-Type": "application/json"
        }
        mock_response.json.return_value = {"error": "Not found"}
        return mock_response

    def mock_get(url, **kwargs):
        """Mock GET request."""
        return create_mock_response('GET', url)

    def mock_post(url, **kwargs):
        """Mock POST request."""
        return create_mock_response('POST', url)

    # Set up patches once at the beginning
    mocker.patch('requests.Session.get', side_effect=mock_get)
    mocker.patch('requests.Session.post', side_effect=mock_post)
    mocker.patch('requests.Session.put', side_effect=mock_post)
    mocker.patch('requests.Session.delete', side_effect=mock_get)

    def setup_single_endpoint_mock(endpoint, response_data, status_code=200, headers=None):
        """Set up mock for a single endpoint (for unit tests)."""
        # Store this endpoint mock
        endpoint_mocks[endpoint] = {
            'response_data': response_data,
            'status_code': status_code,
            'headers': headers
        }

    def setup_sequential_mock(scenario_or_endpoint=None, response_data=None, status_code=200, headers=None):
        """
        Set up mock that can handle multiple sequential responses.

        Can be called in two ways:
        1. New style: setup_sequential_mock('scenario') for component tests
        2. Old style: setup_sequential_mock('/endpoint', response_data, status_code, headers) for unit tests
        """
        # Check if this is the old-style unit test API call
        if response_data is not None:
            # Old API: mock_http_boundary('/endpoint', response_data, status_code=200, headers=None)
            endpoint = scenario_or_endpoint
            return setup_single_endpoint_mock(endpoint, response_data, status_code, headers)

        # New API: scenario-based mocking for component tests
        scenario = scenario_or_endpoint or 'new_certificate'

        # Define responses for different scenarios
        if scenario == 'existing_certificate':
            list_response = mock_zerossl_api_responses['list_certificates_with_valid_cert']
        elif scenario == 'expiring_certificate':
            list_response = mock_zerossl_api_responses['list_certificates_with_expiring_cert']
        else:
            list_response = mock_zerossl_api_responses['list_certificates_empty']

        # Define validation response based on scenario
        if scenario == 'validation_error':
            validation_response = mock_zerossl_api_responses['validation_error']
            validation_status_code = 400
        else:
            validation_response = mock_zerossl_api_responses['validation_success']
            validation_status_code = 200

        # Define certificate creation response based on scenario
        if scenario == 'rate_limit_error':
            create_response = mock_zerossl_api_responses['rate_limit_error']
            create_status_code = 429
        elif scenario == 'auth_error':
            create_response = mock_zerossl_api_responses['auth_error']
            create_status_code = 401
        else:
            create_response = mock_zerossl_api_responses['create_certificate_success']
            create_status_code = 200

        # Define download response based on scenario
        if scenario == 'download_error':
            download_response = mock_zerossl_api_responses['download_error']
            download_status_code = 404
        else:
            download_response = 'ZIP_CONTENT'
            download_status_code = 200

        # Define responses for different URLs/methods based on common workflows
        responses = {
            # GET /certificates - list certificates (check existing)
            ('GET', '/certificates'): list_response,
            # POST /certificates - create certificate
            ('POST', '/certificates'): create_response,
            # POST /certificates/{id}/challenges - validate certificate
            ('POST', '/certificates/test_cert_success_123/challenges'): validation_response,
            # GET /certificates/{id} - get certificate status
            ('GET', '/certificates/test_cert_success_123'): {
                'id': 'test_cert_success_123',
                'status': 'issued',
                'common_name': 'example.com',
                'domains': ['example.com']
            },
            # GET /certificates/{id} - get expiring certificate status
            ('GET', '/certificates/expiring_cert_123'): {
                'id': 'expiring_cert_123',
                'status': 'issued',
                'common_name': 'example.com',
                'expires': '2025-10-01 12:00:00',
                'domains': ['example.com']
            },
            # GET /certificates/{id}/download - download certificate (ZIP file)
            ('GET', '/certificates/test_cert_success_123/download'): download_response
        }

        def mock_request(method, url, **kwargs):
            """Mock function that returns different responses based on method and URL."""
            # Extract the path from the full URL
            if '?' in url:
                path = url.split('?')[0].replace('https://api.zerossl.com', '')
            else:
                path = url.replace('https://api.zerossl.com', '')

            # Find matching response
            key = (method, path)
            if key in responses:
                response_data = responses[key]
            else:
                # Check for pattern matches (e.g., certificate ID endpoints)
                for (resp_method, resp_path), resp_data in responses.items():
                    # Check for test_cert_success_123 patterns
                    if (resp_method == method and 'test_cert_success_123' in resp_path and 'test_cert_success_123' in path):
                        if (('challenges' in resp_path and 'challenges' in path) or
                            ('download' in resp_path and 'download' in path) or
                            (resp_path.endswith('/test_cert_success_123') and path.endswith('/test_cert_success_123'))):
                            response_data = resp_data
                            break
                    # Check for expiring_cert_123 patterns
                    elif (resp_method == method and 'expiring_cert_123' in resp_path and 'expiring_cert_123' in path):
                        if (resp_path.endswith('/expiring_cert_123') and path.endswith('/expiring_cert_123')):
                            response_data = resp_data
                            break
                else:
                    response_data = {"error": "Not mocked"}

            # Create mock response with appropriate status code
            mock_response = Mock()
            # Set appropriate status code based on response type
            if (method == 'POST' and 'challenges' in path and response_data == validation_response):
                mock_response.status_code = validation_status_code
            elif (method == 'POST' and path == '/certificates' and response_data == create_response):
                mock_response.status_code = create_status_code
            elif (method == 'GET' and 'download' in path and response_data == download_response and download_response != 'ZIP_CONTENT'):
                mock_response.status_code = download_status_code
            else:
                mock_response.status_code = 200
            mock_response.headers = {
                "X-Rate-Limit-Remaining": "999",
                "X-Rate-Limit-Limit": "1000",
                "Content-Type": "application/json"
            }

            # Handle different response types
            if response_data == 'ZIP_CONTENT':
                # Create a minimal ZIP file for testing
                import zipfile
                import io
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
                    zip_file.writestr('certificate.crt', '-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----')
                    zip_file.writestr('private.key', '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----')
                    zip_file.writestr('ca_bundle.crt', '-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----')
                mock_response.content = zip_buffer.getvalue()
                mock_response.headers["Content-Type"] = "application/zip"
                mock_response.json = Mock(side_effect=Exception("Not JSON"))
            elif isinstance(response_data, dict) and 'error' in response_data:
                # Error response - both JSON and content should contain the error
                mock_response.json.return_value = response_data
                mock_response.content = json.dumps(response_data).encode()
            else:
                # Regular JSON response
                mock_response.json.return_value = response_data
                mock_response.content = json.dumps(response_data).encode() if response_data else b''

            return mock_response

        # Set up the sequential mock function
        mocker.patch('requests.Session.get', side_effect=lambda url, **kwargs: mock_request('GET', url, **kwargs))
        mocker.patch('requests.Session.post', side_effect=lambda url, **kwargs: mock_request('POST', url, **kwargs))

        return mock_request

    return setup_sequential_mock


@pytest.fixture
def real_certificate_manager(sample_api_key):
    """
    Use real CertificateManager - no mocking of business logic.

    This fixture provides actual CertificateManager instances for testing
    real code paths with only external HTTP calls mocked.
    """
    from plugins.module_utils.zerossl.certificate_manager import CertificateManager
    return CertificateManager(sample_api_key)


@pytest.fixture
def real_api_client(sample_api_key):
    """
    Use real ZeroSSL API client - no mocking of business logic.

    This fixture provides actual ZeroSSLAPIClient instances for testing
    real code paths with only external HTTP calls mocked.
    """
    from plugins.module_utils.zerossl.api_client import ZeroSSLAPIClient
    return ZeroSSLAPIClient(sample_api_key)


@pytest.fixture
def realistic_certificate_data():
    """Realistic certificate data from fixtures directory."""
    fixtures_dir = Path(__file__).parent / "fixtures" / "certificate_data"

    def load_pem_file(filename):
        try:
            with open(fixtures_dir / filename, 'r') as f:
                return f.read()
        except FileNotFoundError:
            # Fallback to sample data if fixture files don't exist yet
            return ""

    return {
        "certificate_pem": load_pem_file("sample_certificate.pem"),
        "private_key_pem": load_pem_file("sample_private_key.pem"),
        "ca_bundle_pem": load_pem_file("sample_ca_bundle.pem"),
        "csr_pem": load_pem_file("sample_csr.pem"),
    }


@pytest.fixture
def mock_ansible_environment(mock_action_base, mock_task_vars):
    """
    Complete Ansible environment for component testing.

    Provides all necessary Ansible context objects for testing
    ActionModule instances with real method calls.
    """
    return Mock(
        task=mock_action_base._task,
        connection=Mock(),
        play_context=Mock(),
        loader=Mock(),
        templar=Mock(),
        shared_loader_obj=Mock(),
        task_vars=mock_task_vars
    )


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
