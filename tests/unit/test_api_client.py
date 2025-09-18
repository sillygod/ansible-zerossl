# -*- coding: utf-8 -*-
"""
Unit tests for ZeroSSL API client.

These tests verify the API client functionality in isolation,
focusing on HTTP requests, response handling, and error management.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from plugins.module_utils.zerossl.api_client import ZeroSSLAPIClient
from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError, ZeroSSLValidationError, ZeroSSLConfigurationError, ZeroSSLRateLimitError


@pytest.mark.unit
class TestZeroSSLAPIClient:
    """Unit tests for ZeroSSL API client."""

    def test_api_client_initialization(self, sample_api_key):
        """Test API client initialization."""
        client = ZeroSSLAPIClient(sample_api_key)

        assert client.api_key == sample_api_key
        assert client.base_url == "https://api.zerossl.com"
        assert client.max_retries == 3  # Default value
        assert client.timeout == 30     # Default value

    def test_api_client_custom_configuration(self):
        """Test API client with custom configuration."""
        custom_config = {
            'api_key': 'custom_api_key_1234567890_abcdef',
            'base_url': 'https://custom.zerossl.com',
            'max_retries': 5,
            'timeout': 60
        }

        client = ZeroSSLAPIClient(**custom_config)

        assert client.api_key == 'custom_api_key_1234567890_abcdef'
        assert client.base_url == 'https://custom.zerossl.com'
        assert client.max_retries == 5
        assert client.timeout == 60

    def test_build_request_url(self, sample_api_key):
        """Test URL building for API requests."""
        client = ZeroSSLAPIClient(sample_api_key)

        # Test certificate endpoint
        cert_url = client._build_url('/certificates')
        assert cert_url.startswith('https://api.zerossl.com/certificates')
        assert 'access_key=' in cert_url

        # Test certificate with ID
        cert_id_url = client._build_url(f'/certificates/12345')
        assert cert_id_url.startswith('https://api.zerossl.com/certificates/12345')
        assert 'access_key=' in cert_id_url

        # Test with query parameters
        url_with_params = client._build_url('/certificates', {'status': 'issued'})
        assert 'access_key=' in url_with_params
        assert 'status=issued' in url_with_params

    def test_request_headers_construction(self, sample_api_key):
        """Test HTTP request headers construction."""
        client = ZeroSSLAPIClient(sample_api_key)

        headers = client._build_headers()

        assert 'User-Agent' in headers
        assert 'ansible-zerossl' in headers['User-Agent'].lower()
        assert headers['Accept'] == 'application/json'

    def test_authentication_parameter_injection(self, sample_api_key):
        """Test that API key is properly injected into requests."""
        client = ZeroSSLAPIClient(sample_api_key)

        # Test GET request params
        params = client._add_auth({'status': 'issued'})
        assert 'access_key' in params
        assert params['access_key'] == sample_api_key
        assert params['status'] == 'issued'

        # Test empty params
        empty_params = client._add_auth({})
        assert empty_params == {'access_key': sample_api_key}

    def test_http_get_request(self, sample_api_key):
        """Test HTTP GET request execution."""
        client = ZeroSSLAPIClient(sample_api_key)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'result': 'success'}
        mock_response.headers = {}

        with patch.object(client.session, 'get', return_value=mock_response) as mock_get:
            result = client._make_request('GET', '/certificates')

            assert result == {'result': 'success'}
            mock_get.assert_called_once()

    def test_http_post_request(self, sample_api_key):
        """Test HTTP POST request execution."""
        client = ZeroSSLAPIClient(sample_api_key)

        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {'id': 'new_cert_123'}
        mock_response.headers = {}

        post_data = {
            'certificate_domains': 'example.com',
            'certificate_csr': 'csr_content'
        }

        with patch.object(client.session, 'post', return_value=mock_response) as mock_post:
            result = client._make_request('POST', '/certificates', data=post_data)

            assert result == {'id': 'new_cert_123'}
            mock_post.assert_called_once()


    def test_rate_limit_handling(self, sample_api_key):
        """Test rate limit handling - should raise ZeroSSLRateLimitError."""
        client = ZeroSSLAPIClient(sample_api_key, max_retries=2)

        # Return 429 rate limit response
        rate_limit_response = Mock()
        rate_limit_response.status_code = 429
        rate_limit_response.json.return_value = {'error': 'rate_limit_exceeded'}
        rate_limit_response.headers = {}

        with patch.object(client.session, 'get', return_value=rate_limit_response) as mock_get:
            with pytest.raises(ZeroSSLRateLimitError):
                client._make_request('GET', '/certificates')

    def test_retry_exhaustion(self, sample_api_key):
        """Test behavior when retry attempts are exhausted."""
        client = ZeroSSLAPIClient(sample_api_key, max_retries=1)

        # Always return 500 error
        error_response = Mock()
        error_response.status_code = 500
        error_response.json.return_value = {'error': 'server_error'}
        error_response.headers = {}

        with patch.object(client.session, 'get', return_value=error_response):
            with patch('time.sleep'):
                with pytest.raises(ZeroSSLHTTPError, match="server_error"):
                    client._make_request('GET', '/certificates')

    def test_json_parsing_error_handling(self, sample_api_key):
        """Test handling of malformed JSON responses."""
        client = ZeroSSLAPIClient(sample_api_key)

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.text = "Invalid JSON response"
        mock_response.headers = {}

        with patch.object(client.session, 'get', return_value=mock_response):
            with pytest.raises(ZeroSSLHTTPError, match="Invalid JSON"):
                client._make_request('GET', '/certificates')

    def test_network_timeout_handling(self, sample_api_key):
        """Test network timeout handling."""
        client = ZeroSSLAPIClient(sample_api_key, timeout=1)

        import requests
        with patch.object(client.session, 'get', side_effect=requests.RequestException("Connection timeout")):
            with pytest.raises(ZeroSSLHTTPError, match="Request failed"):
                client._make_request('GET', '/certificates')

    def test_create_certificate_method(self, sample_api_key, sample_domains, sample_csr):
        """Test create_certificate method."""
        client = ZeroSSLAPIClient(sample_api_key)

        expected_response = {
            'id': 'cert_123',
            'status': 'draft',
            'validation': {'other_methods': {}}
        }

        with patch.object(client, '_make_request', return_value=expected_response) as mock_request:
            result = client.create_certificate(sample_domains, sample_csr)

            assert result == expected_response
            mock_request.assert_called_once()

            # Verify request parameters
            call_args = mock_request.call_args
            assert call_args[0][0] == 'POST'  # Method
            assert call_args[0][1] == '/certificates'  # Endpoint

            # Verify data
            request_data = call_args[1]['data']
            assert request_data['certificate_domains'] == ','.join(sample_domains)
            assert request_data['certificate_csr'] == sample_csr

    def test_get_certificate_method(self, sample_api_key):
        """Test get_certificate method."""
        client = ZeroSSLAPIClient(sample_api_key)
        certificate_id = 'cert_123'

        expected_response = {
            'id': certificate_id,
            'status': 'issued',
            'expires': '2025-12-17 12:00:00'
        }

        with patch.object(client, '_make_request', return_value=expected_response) as mock_request:
            result = client.get_certificate(certificate_id)

            assert result == expected_response
            mock_request.assert_called_once_with('GET', f'/certificates/{certificate_id}')

    def test_list_certificates_method(self, sample_api_key):
        """Test list_certificates method."""
        client = ZeroSSLAPIClient(sample_api_key)

        expected_response = {
            'total_count': 10,
            'results': [{'id': f'cert_{i}'} for i in range(5)]
        }

        with patch.object(client, '_make_request', return_value=expected_response) as mock_request:
            result = client.list_certificates(status='issued', page=1)

            assert result == expected_response
            mock_request.assert_called_once()

            # Verify query parameters
            call_args = mock_request.call_args
            assert call_args[1]['params']['status'] == 'issued'
            assert call_args[1]['params']['page'] == 1

    def test_validate_certificate_method(self, sample_api_key):
        """Test validate_certificate method."""
        client = ZeroSSLAPIClient(sample_api_key)
        certificate_id = 'cert_123'
        validation_method = 'HTTP_CSR_HASH'

        expected_response = {
            'success': True,
            'validation_completed': True
        }

        with patch.object(client, '_make_request', return_value=expected_response) as mock_request:
            result = client.validate_certificate(certificate_id, validation_method)

            assert result == expected_response
            mock_request.assert_called_once()

            # Verify request
            call_args = mock_request.call_args
            assert call_args[0][0] == 'POST'
            assert call_args[0][1] == f'/certificates/{certificate_id}/challenges'
            assert call_args[1]['json']['validation_method'] == validation_method

    def test_download_certificate_method(self, sample_api_key):
        """Test download_certificate method."""
        client = ZeroSSLAPIClient(sample_api_key)
        certificate_id = 'cert_123'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'certificate_zip_content'

        with patch.object(client.session, 'get', return_value=mock_response) as mock_get:
            result = client.download_certificate(certificate_id)

            assert result == b'certificate_zip_content'
            mock_get.assert_called_once()

    def test_input_validation(self, sample_api_key):
        """Test input parameter validation."""
        client = ZeroSSLAPIClient(sample_api_key)

        # Test empty domains
        with pytest.raises(ZeroSSLConfigurationError, match="At least one domain is required"):
            client.create_certificate([], "valid_csr")

        # Test invalid domain format
        with pytest.raises(ZeroSSLConfigurationError, match="must have at least two labels"):
            client.create_certificate(["invalid_domain!"], "valid_csr")

        # Test empty CSR
        with pytest.raises(ZeroSSLConfigurationError, match="CSR content is required"):
            client.create_certificate(["example.com"], "")

        # Test invalid certificate ID
        with pytest.raises(ZeroSSLConfigurationError, match="certificate_id is required"):
            client.get_certificate("")

    def test_error_response_parsing(self, sample_api_key):
        """Test parsing of error responses from API."""
        client = ZeroSSLAPIClient(sample_api_key)

        error_responses = [
            (400, {'error': {'code': 400, 'message': 'Bad request'}}),
            (401, {'error': {'code': 401, 'message': 'Unauthorized'}}),
            (404, {'error': {'code': 404, 'message': 'Not found'}}),
            (500, {'error': {'code': 500, 'message': 'Server error'}})
        ]

        for status_code, error_data in error_responses:
            mock_response = Mock()
            mock_response.status_code = status_code
            mock_response.json.return_value = error_data
            mock_response.headers = {}

            with patch.object(client.session, 'get', return_value=mock_response):
                with pytest.raises(ZeroSSLHTTPError) as exc_info:
                    client._make_request('GET', '/certificates')

                assert str(status_code) in str(exc_info.value)

    def test_concurrent_request_handling(self, sample_api_key):
        """Test handling of concurrent API requests."""
        client = ZeroSSLAPIClient(sample_api_key)

        # This would test thread safety and connection pooling
        # For now, verify basic functionality
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'result': 'concurrent_success'}
        mock_response.headers = {}

        with patch.object(client.session, 'get', return_value=mock_response):
            # Simulate multiple concurrent requests
            results = []
            for i in range(5):
                result = client._make_request('GET', f'/certificates/cert_{i}')
                results.append(result)

            assert len(results) == 5
            assert all(r['result'] == 'concurrent_success' for r in results)

    def test_api_client_cleanup(self, sample_api_key):
        """Test proper cleanup of API client resources."""
        client = ZeroSSLAPIClient(sample_api_key)

        # Test that client can be properly disposed
        assert hasattr(client, 'close') or hasattr(client, '__del__')

        # Verify no exceptions during cleanup
        try:
            if hasattr(client, 'close'):
                client.close()
            del client
        except Exception as e:
            pytest.fail(f"API client cleanup failed: {e}")
