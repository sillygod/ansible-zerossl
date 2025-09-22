# -*- coding: utf-8 -*-
"""
Contract tests for ZeroSSL API integration.

These tests verify that the ZeroSSL API behaves as expected according to
the API specification. They test the contract between our plugin and
the ZeroSSL service.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from plugins.module_utils.zerossl.api_client import ZeroSSLAPIClient
from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError, ZeroSSLValidationError, ZeroSSLConfigurationError


@pytest.mark.contract
class TestZeroSSLCertificateCreationContract:
    """Test contract for ZeroSSL certificate creation API."""

    def test_create_certificate_valid_request_format(self, sample_api_key, sample_domains, sample_csr):
        """Test that certificate creation request matches expected format."""
        # This test will fail until APIClient is implemented
        client = ZeroSSLAPIClient(sample_api_key)

        expected_request_data = {
            'certificate_domains': ','.join(sample_domains),
            'certificate_csr': sample_csr,
            'certificate_validity_days': 90
        }

        with patch.object(client.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.json.return_value = {
                "id": "test_cert_123456789",
                "status": "draft",
                "validation": {"other_methods": {}}
            }
            mock_post.return_value = mock_response

            # This should call the API with correct format
            result = client.create_certificate(sample_domains, sample_csr)

            # Verify request was made with correct data
            mock_post.assert_called_once()
            call_args = mock_post.call_args

            # Check the URL contains access_key parameter
            assert 'https://api.zerossl.com/certificates' in call_args[0][0]
            assert 'access_key=' in call_args[0][0]
            # Check the data contains expected fields (but not access_key since it's in URL)
            assert 'certificate_domains' in call_args[1]['data']
            assert 'certificate_csr' in call_args[1]['data']
            assert 'certificate_validity_days' in call_args[1]['data']

    def test_create_certificate_response_structure(self, sample_api_key, sample_domains, sample_csr):
        """Test that certificate creation response has expected structure."""
        client = ZeroSSLAPIClient(sample_api_key)

        expected_response_fields = [
            'id', 'status', 'common_name', 'validation'
        ]

        with patch.object(client.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.json.return_value = {
                "id": "test_cert_123456789",
                "status": "draft",
                "common_name": "example.com",
                "validation": {
                    "other_methods": {
                        "example.com": {
                            "file_validation_url_http": "http://example.com/.well-known/pki-validation/test.txt",
                            "file_validation_content": "test_content"
                        }
                    }
                }
            }
            mock_post.return_value = mock_response

            result = client.create_certificate(sample_domains, sample_csr)

            # Verify response structure
            for field in expected_response_fields:
                assert field in result, f"Missing field: {field}"

            assert isinstance(result['validation'], dict)
            assert 'other_methods' in result['validation']

    def test_create_certificate_handles_api_errors(self, sample_api_key, sample_domains, sample_csr):
        """Test that API errors are properly handled."""
        client = ZeroSSLAPIClient(sample_api_key)

        error_responses = [
            (400, {"error": {"code": 400, "type": "invalid_request"}}),
            (401, {"error": {"code": 401, "type": "unauthorized"}}),
            (429, {"error": {"code": 429, "type": "rate_limit_exceeded"}})
        ]

        for status_code, error_data in error_responses:
            with patch.object(client.session, 'post') as mock_post:
                mock_response = Mock()
                mock_response.status_code = status_code
                mock_response.json.return_value = error_data
                mock_response.headers = {}  # Add empty headers dict
                mock_post.return_value = mock_response

                with pytest.raises(ZeroSSLHTTPError) as exc_info:
                    client.create_certificate(sample_domains, sample_csr)

                assert str(status_code) in str(exc_info.value)

    def test_create_certificate_validates_input_parameters(self, sample_api_key):
        """Test that input parameters are validated."""
        client = ZeroSSLAPIClient(sample_api_key)

        # Test empty domains
        with pytest.raises(ZeroSSLConfigurationError, match="At least one domain is required"):
            client.create_certificate([], "valid_csr")

        # Test invalid domains
        with pytest.raises(ZeroSSLConfigurationError, match="must have at least two labels"):
            client.create_certificate(["invalid_domain_!@#"], "valid_csr")

        # Test empty CSR
        with pytest.raises(ZeroSSLConfigurationError, match="CSR content is required"):
            client.create_certificate(["example.com"], "")

    def test_create_certificate_handles_request_exceptions(self, sample_api_key, sample_domains, sample_csr):
        """Test that request exceptions are properly handled."""
        client = ZeroSSLAPIClient(sample_api_key, max_retries=2)

        with patch.object(client.session, 'post') as mock_post:
            # Request exception should be caught and converted to ZeroSSLHTTPError
            import requests
            mock_post.side_effect = requests.exceptions.Timeout("Request timeout")

            with pytest.raises(ZeroSSLHTTPError, match="Request failed"):
                client.create_certificate(sample_domains, sample_csr)

            # Verify the exception was handled
            assert mock_post.call_count >= 1


@pytest.mark.contract
class TestZeroSSLCertificateRetrievalContract:
    """Test contract for ZeroSSL certificate retrieval operations."""

    def test_get_certificate_by_id_format(self, sample_api_key):
        """Test getting certificate by ID matches expected format."""
        client = ZeroSSLAPIClient(sample_api_key)
        certificate_id = "test_cert_123456789"

        with patch.object(client.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.json.return_value = {
                "id": certificate_id,
                "status": "issued",
                "common_name": "example.com",
                "expires": "2025-12-16 12:00:00"
            }
            mock_get.return_value = mock_response

            result = client.get_certificate(certificate_id)

            # Verify API call format
            mock_get.assert_called_once()
            call_args = mock_get.call_args
            expected_url = f"https://api.zerossl.com/certificates/{certificate_id}"
            assert expected_url in call_args[0][0]  # URL is first positional argument

    def test_list_certificates_pagination(self, sample_api_key):
        """Test certificate listing with pagination."""
        client = ZeroSSLAPIClient(sample_api_key)

        with patch.object(client.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.json.return_value = {
                "total_count": 150,
                "result_count": 100,
                "page": 1,
                "results": [{"id": f"cert_{i}"} for i in range(100)]
            }
            mock_get.return_value = mock_response

            result = client.list_certificates(page=1, limit=100)

            assert result['total_count'] == 150
            assert len(result['results']) == 100
            assert result['page'] == 1

    def test_download_certificate_format(self, sample_api_key):
        """Test certificate download returns proper format."""
        client = ZeroSSLAPIClient(sample_api_key)
        certificate_id = "test_cert_123456789"

        with patch.object(client.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.content = b'fake_zip_content'
            mock_response.headers = {'content-type': 'application/zip'}
            mock_get.return_value = mock_response

            result = client.download_certificate(certificate_id)

            # Verify download call
            mock_get.assert_called_once()
            call_args = mock_get.call_args
            expected_url = f"https://api.zerossl.com/certificates/{certificate_id}/download"
            assert expected_url in call_args[0][0]  # URL is first positional argument

            assert isinstance(result, bytes)


@pytest.mark.contract
class TestZeroSSLValidationContract:
    """Test contract for ZeroSSL domain validation operations."""

    def test_validate_certificate_request_format(self, sample_api_key):
        """Test validation request format."""
        client = ZeroSSLAPIClient(sample_api_key)
        certificate_id = "test_cert_123456789"
        validation_method = "HTTP_CSR_HASH"

        with patch.object(client.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.json.return_value = {
                "success": True,
                "validation_completed": False
            }
            mock_post.return_value = mock_response

            result = client.validate_certificate(certificate_id, validation_method)

            # Verify request format
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            expected_url = f"https://api.zerossl.com/certificates/{certificate_id}/challenges"
            assert expected_url in call_args[0][0]  # URL is first positional argument

            # Verify request body
            expected_data = {"validation_method": validation_method}
            call_data = call_args[1]['json']  # JSON data is passed directly, not as string
            assert call_data == expected_data

    def test_validation_methods_supported(self, sample_api_key):
        """Test that supported validation methods work."""
        client = ZeroSSLAPIClient(sample_api_key)
        certificate_id = "test_cert_123456789"

        supported_methods = ["HTTP_CSR_HASH", "DNS_CSR_HASH"]

        for method in supported_methods:
            with patch.object(client.session, 'post') as mock_post:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.headers = {}
                mock_response.json.return_value = {"success": True}
                mock_post.return_value = mock_response

                # Should not raise an exception
                result = client.validate_certificate(certificate_id, method)
                assert result['success'] is True

    def test_validation_error_handling(self, sample_api_key):
        """Test validation error scenarios."""
        client = ZeroSSLAPIClient(sample_api_key)
        certificate_id = "test_cert_123456789"

        with patch.object(client.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.headers = {}
            mock_response.json.return_value = {
                "error": {"type": "validation_failed", "details": "Domain not accessible"}
            }
            mock_post.return_value = mock_response

            with pytest.raises(ZeroSSLHTTPError):
                client.validate_certificate(certificate_id, "HTTP_CSR_HASH")


# Test fixtures that will be used across tests
@pytest.fixture
def mock_api_client(sample_api_key):
    """Mock API client for testing."""
    return ZeroSSLAPIClient(sample_api_key)
