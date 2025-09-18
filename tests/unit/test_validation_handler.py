# -*- coding: utf-8 -*-
"""
Unit tests for ZeroSSL Validation Handler.

These tests verify domain validation functionality including
HTTP-01 and DNS-01 validation methods.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from plugins.module_utils.zerossl.validation_handler import ValidationHandler
from plugins.module_utils.zerossl.exceptions import ZeroSSLValidationError


@pytest.mark.unit
class TestValidationHandler:
    """Unit tests for Validation Handler."""

    def test_validation_handler_initialization(self):
        """Test validation handler initialization."""
        handler = ValidationHandler()

        assert hasattr(handler, 'http_timeout')
        assert hasattr(handler, 'dns_timeout')
        assert handler.http_timeout == 30  # Default value
        assert handler.dns_timeout == 60   # Default value

    def test_validation_handler_custom_config(self):
        """Test validation handler with custom configuration."""
        config = {
            'http_timeout': 45,
            'dns_timeout': 120,
            'max_retries': 5
        }

        handler = ValidationHandler(**config)

        assert handler.http_timeout == 45
        assert handler.dns_timeout == 120
        assert handler.max_retries == 5

    def test_prepare_http_validation_files(self, sample_domains):
        """Test preparation of HTTP validation files."""
        handler = ValidationHandler()

        validation_data = {
            'example.com': {
                'file_validation_url_http': 'http://example.com/.well-known/pki-validation/test123.txt',
                'file_validation_content': 'validation_content_123'
            },
            'www.example.com': {
                'file_validation_url_http': 'http://www.example.com/.well-known/pki-validation/test456.txt',
                'file_validation_content': 'validation_content_456'
            }
        }

        validation_files = handler.prepare_http_validation(validation_data)

        assert len(validation_files) == 2

        for vf in validation_files:
            assert 'domain' in vf
            assert 'filename' in vf
            assert 'content' in vf
            assert 'url_path' in vf
            assert vf['domain'] in sample_domains
            assert vf['url_path'].startswith('/.well-known/pki-validation/')
            assert vf['filename'].endswith('.txt')

    def test_extract_validation_filename(self):
        """Test extraction of validation filename from URL."""
        handler = ValidationHandler()

        test_urls = [
            ('http://example.com/.well-known/pki-validation/auth123.txt', 'auth123.txt'),
            ('https://secure.com/.well-known/pki-validation/token456.txt', 'token456.txt'),
            ('http://sub.domain.com/.well-known/pki-validation/challenge.txt', 'challenge.txt')
        ]

        for url, expected_filename in test_urls:
            filename = handler._extract_filename_from_url(url)
            assert filename == expected_filename

    def test_validation_file_path_construction(self):
        """Test construction of validation file paths."""
        handler = ValidationHandler()

        base_path = '/var/www/html'
        url_path = '/.well-known/pki-validation/test.txt'

        full_path = handler._construct_file_path(base_path, url_path)
        expected_path = Path(base_path) / '.well-known' / 'pki-validation' / 'test.txt'

        assert full_path == str(expected_path)

    def test_place_validation_files(self, temp_directory):
        """Test placing validation files in filesystem."""
        handler = ValidationHandler()

        validation_files = [
            {
                'domain': 'example.com',
                'filename': 'test123.txt',
                'content': 'validation_content_123',
                'url_path': '/.well-known/pki-validation/test123.txt'
            },
            {
                'domain': 'www.example.com',
                'filename': 'test456.txt',
                'content': 'validation_content_456',
                'url_path': '/.well-known/pki-validation/test456.txt'
            }
        ]

        result = handler.place_validation_files(validation_files, str(temp_directory))

        assert result['success'] is True
        assert len(result['files_created']) == 2

        # Verify files were created
        for file_info in result['files_created']:
            file_path = Path(file_info['path'])
            assert file_path.exists()

            # Verify content
            content = file_path.read_text()
            expected_content = next(vf['content'] for vf in validation_files
                                  if vf['filename'] == file_path.name)
            assert content == expected_content

    def test_place_validation_files_permission_error(self, temp_directory):
        """Test handling of permission errors when placing files."""
        handler = ValidationHandler()

        validation_files = [
            {
                'domain': 'example.com',
                'filename': 'permission_test.txt',
                'content': 'test_content',
                'url_path': '/.well-known/pki-validation/permission_test.txt'
            }
        ]

        # Mock permission error
        with patch('pathlib.Path.mkdir', side_effect=PermissionError("Permission denied")):
            result = handler.place_validation_files(validation_files, str(temp_directory))

            assert result['success'] is False
            assert 'permission' in result['error'].lower()

    def test_verify_http_validation_success(self):
        """Test HTTP validation verification - success case."""
        handler = ValidationHandler()

        validation_url = 'http://example.com/.well-known/pki-validation/test.txt'
        expected_content = 'validation_content_123'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = expected_content

        with patch('requests.get', return_value=mock_response) as mock_get:
            result = handler.verify_http_validation(validation_url, expected_content)

            assert result['accessible'] is True
            assert result['content_match'] is True
            assert result['status_code'] == 200

            mock_get.assert_called_once_with(validation_url, timeout=30)

    def test_verify_http_validation_failure_scenarios(self):
        """Test HTTP validation verification - failure scenarios."""
        handler = ValidationHandler()

        validation_url = 'http://example.com/.well-known/pki-validation/test.txt'
        expected_content = 'expected_content'

        failure_scenarios = [
            (404, 'File not found', False, False),
            (403, 'Access forbidden', False, False),
            (500, 'Server error', False, False),
            (200, 'wrong_content', True, False)  # Accessible but wrong content
        ]

        for status_code, response_text, expected_accessible, expected_match in failure_scenarios:
            mock_response = Mock()
            mock_response.status_code = status_code
            mock_response.text = response_text

            with patch('requests.get', return_value=mock_response):
                result = handler.verify_http_validation(validation_url, expected_content)

                assert result['accessible'] == expected_accessible
                assert result['content_match'] == expected_match
                assert result['status_code'] == status_code

    def test_verify_http_validation_network_error(self):
        """Test HTTP validation with network errors."""
        handler = ValidationHandler()

        validation_url = 'http://unreachable.example.com/.well-known/pki-validation/test.txt'
        expected_content = 'content'

        with patch('requests.get', side_effect=Exception("Connection failed")):
            result = handler.verify_http_validation(validation_url, expected_content)

            assert result['accessible'] is False
            assert result['content_match'] is False
            assert 'error' in result
            assert 'connection' in result['error'].lower()

    def test_prepare_dns_validation_records(self):
        """Test preparation of DNS validation records."""
        handler = ValidationHandler()

        validation_data = {
            'example.com': {
                'dns_txt_name': '_acme-challenge.example.com',
                'dns_txt_value': 'dns_challenge_token_123'
            },
            'www.example.com': {
                'dns_txt_name': '_acme-challenge.www.example.com',
                'dns_txt_value': 'dns_challenge_token_456'
            }
        }

        dns_records = handler.prepare_dns_validation(validation_data)

        assert len(dns_records) == 2

        for record in dns_records:
            assert 'domain' in record
            assert 'record_name' in record
            assert 'record_type' in record
            assert 'record_value' in record
            assert record['record_type'] == 'TXT'
            assert record['record_name'].startswith('_acme-challenge.')

    def test_dns_record_name_parsing(self):
        """Test parsing of DNS record names."""
        handler = ValidationHandler()

        test_cases = [
            ('_acme-challenge.example.com', '_acme-challenge.example.com'),
            ('_acme-challenge.sub.example.com', '_acme-challenge.sub.example.com'),
            ('_acme-challenge.long.subdomain.example.com', '_acme-challenge.long.subdomain.example.com')
        ]

        for input_name, expected_name in test_cases:
            parsed_name = handler._parse_dns_record_name(input_name)
            assert parsed_name == expected_name

    def test_generate_dns_instructions(self):
        """Test generation of DNS instructions for users."""
        handler = ValidationHandler()

        dns_records = [
            {
                'domain': 'example.com',
                'record_name': '_acme-challenge.example.com',
                'record_type': 'TXT',
                'record_value': 'dns_token_123'
            },
            {
                'domain': 'www.example.com',
                'record_name': '_acme-challenge.www.example.com',
                'record_type': 'TXT',
                'record_value': 'dns_token_456'
            }
        ]

        instructions = handler.generate_dns_instructions(dns_records)

        assert 'records_to_create' in instructions
        assert len(instructions['records_to_create']) == 2
        assert 'instructions' in instructions
        assert isinstance(instructions['instructions'], str)
        assert 'TXT' in instructions['instructions']

    def test_verify_dns_validation_success(self):
        """Test DNS validation verification - success case."""
        handler = ValidationHandler()

        record_name = '_acme-challenge.example.com'
        expected_value = 'dns_challenge_token_123'

        # Mock DNS resolution
        mock_record = Mock()
        mock_record.to_text.return_value = f'"{expected_value}"'

        with patch('dns.resolver.resolve', return_value=[mock_record]) as mock_resolve:
            result = handler.verify_dns_validation(record_name, expected_value)

            assert result['record_exists'] is True
            assert result['value_match'] is True
            mock_resolve.assert_called_once_with(record_name, 'TXT')

    def test_verify_dns_validation_failure_scenarios(self):
        """Test DNS validation verification - failure scenarios."""
        handler = ValidationHandler()

        record_name = '_acme-challenge.example.com'
        expected_value = 'expected_token'

        # Test DNS resolution failure (NXDOMAIN)
        from dns.resolver import NXDOMAIN
        with patch('dns.resolver.resolve', side_effect=NXDOMAIN()):
            result = handler.verify_dns_validation(record_name, expected_value)

            assert result['record_exists'] is False
            assert result['value_match'] is False

        # Test wrong DNS value
        mock_record = Mock()
        mock_record.to_text.return_value = '"wrong_token"'

        with patch('dns.resolver.resolve', return_value=[mock_record]):
            result = handler.verify_dns_validation(record_name, expected_value)

            assert result['record_exists'] is True
            assert result['value_match'] is False

    def test_wildcard_domain_dns_handling(self):
        """Test DNS validation for wildcard domains."""
        handler = ValidationHandler()

        wildcard_validation_data = {
            '*.example.com': {
                'dns_txt_name': '_acme-challenge.example.com',  # Base domain
                'dns_txt_value': 'wildcard_challenge_token'
            }
        }

        dns_records = handler.prepare_dns_validation(wildcard_validation_data)

        assert len(dns_records) == 1
        record = dns_records[0]

        assert record['domain'] == '*.example.com'
        assert record['record_name'] == '_acme-challenge.example.com'
        assert record['record_value'] == 'wildcard_challenge_token'

    def test_validation_status_polling(self, sample_api_key):
        """Test validation status polling mechanism."""
        handler = ValidationHandler()
        certificate_id = 'polling_test_cert'

        # Mock API client
        mock_api_client = Mock()

        # Simulate validation progression: pending → pending → issued
        status_progression = [
            {'status': 'pending_validation', 'validation_completed': False},
            {'status': 'pending_validation', 'validation_completed': False},
            {'status': 'issued', 'validation_completed': True}
        ]

        mock_api_client.get_certificate.side_effect = status_progression

        result = handler.poll_validation_status(
            mock_api_client,
            certificate_id,
            max_attempts=3,
            poll_interval=0.1  # Fast polling for tests
        )

        assert result['final_status'] == 'issued'
        assert result['validation_completed'] is True
        assert result['attempts'] == 3

    def test_validation_polling_timeout(self, sample_api_key):
        """Test validation polling timeout handling."""
        handler = ValidationHandler()
        certificate_id = 'timeout_test_cert'

        mock_api_client = Mock()
        # Always return pending status
        mock_api_client.get_certificate.return_value = {
            'status': 'pending_validation',
            'validation_completed': False
        }

        with pytest.raises(ZeroSSLValidationError, match="timeout"):
            handler.poll_validation_status(
                mock_api_client,
                certificate_id,
                max_attempts=2,
                poll_interval=0.1
            )

    def test_validation_failure_detection(self, sample_api_key):
        """Test detection of validation failures."""
        handler = ValidationHandler()
        certificate_id = 'failure_test_cert'

        mock_api_client = Mock()

        failure_statuses = ['canceled', 'expired', 'failed']

        for failure_status in failure_statuses:
            mock_api_client.get_certificate.return_value = {
                'status': failure_status,
                'validation_completed': False
            }

            with pytest.raises(ZeroSSLValidationError, match=failure_status):
                handler.poll_validation_status(
                    mock_api_client,
                    certificate_id,
                    max_attempts=1
                )

    def test_validation_method_selection(self):
        """Test automatic validation method selection."""
        handler = ValidationHandler()

        # Test HTTP validation for regular domains
        regular_domains = ['example.com', 'www.example.com']
        method = handler.suggest_validation_method(regular_domains)
        assert method == 'HTTP_CSR_HASH'

        # Test DNS validation for wildcard domains
        wildcard_domains = ['*.example.com', 'example.com']
        method = handler.suggest_validation_method(wildcard_domains)
        assert method == 'DNS_CSR_HASH'

    def test_validation_file_cleanup(self, temp_directory):
        """Test cleanup of validation files."""
        handler = ValidationHandler()

        # Create validation files
        validation_files = [
            {
                'domain': 'example.com',
                'filename': 'cleanup_test.txt',
                'content': 'cleanup_content',
                'url_path': '/.well-known/pki-validation/cleanup_test.txt'
            }
        ]

        # Place files
        place_result = handler.place_validation_files(validation_files, str(temp_directory))
        assert place_result['success'] is True

        # Verify files exist
        created_files = place_result['files_created']
        for file_info in created_files:
            assert Path(file_info['path']).exists()

        # Clean up files
        cleanup_result = handler.cleanup_validation_files(created_files)
        assert cleanup_result['success'] is True

        # Verify files are removed
        for file_info in created_files:
            assert not Path(file_info['path']).exists()

    def test_concurrent_validation_operations(self):
        """Test handling of concurrent validation operations."""
        handler = ValidationHandler()

        # Test that multiple validation operations don't interfere
        validation_urls = [
            f'http://example{i}.com/.well-known/pki-validation/test{i}.txt'
            for i in range(5)
        ]

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'validation_content'

        with patch('requests.get', return_value=mock_response):
            results = []
            for url in validation_urls:
                result = handler.verify_http_validation(url, 'validation_content')
                results.append(result)

            assert len(results) == 5
            assert all(r['accessible'] is True for r in results)
            assert all(r['content_match'] is True for r in results)

    def test_validation_error_aggregation(self):
        """Test aggregation of validation errors from multiple domains."""
        handler = ValidationHandler()

        validation_errors = [
            {'domain': 'example.com', 'error': 'HTTP validation failed'},
            {'domain': 'www.example.com', 'error': 'DNS record not found'},
            {'domain': 'api.example.com', 'error': 'Timeout during validation'}
        ]

        aggregated_error = handler.aggregate_validation_errors(validation_errors)

        assert 'Multiple domains failed validation' in aggregated_error['message']
        assert len(aggregated_error['domain_errors']) == 3
        assert aggregated_error['failed_count'] == 3
