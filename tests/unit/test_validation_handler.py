# -*- coding: utf-8 -*-
"""
Improved Unit Tests for ZeroSSL Validation Handler.

Follows improved test design patterns:
- Mock only at HTTP/filesystem boundaries
- Use real method calls and validation logic
- Test realistic ZeroSSL validation scenarios
- Achieve 80%+ line coverage with performance limits
"""

import pytest
import time
from pathlib import Path
from unittest.mock import Mock
from plugins.module_utils.zerossl.validation_handler import ValidationHandler
from plugins.module_utils.zerossl.exceptions import ZeroSSLValidationError, ZeroSSLFileSystemError


@pytest.mark.unit
class TestValidationHandlerImproved:
    """Improved unit tests for Validation Handler with HTTP boundary mocking only."""

    def test_validation_handler_initialization_defaults(self):
        """Test validation handler initialization with default values."""
        # Act: Create handler with defaults - exercise real constructor
        handler = ValidationHandler()

        # Assert: Verify real instance attributes set correctly
        assert handler.http_timeout == 30
        assert handler.dns_timeout == 60
        assert handler.max_retries == 3
        assert isinstance(handler, ValidationHandler)

    def test_validation_handler_custom_configuration(self):
        """Test validation handler initialization with custom configuration."""
        # Arrange: Custom configuration parameters
        custom_config = {
            'http_timeout': 45,
            'dns_timeout': 120,
            'max_retries': 5
        }

        # Act: Create handler with custom config - exercise real constructor
        handler = ValidationHandler(**custom_config)

        # Assert: Verify all custom parameters set correctly
        assert handler.http_timeout == 45
        assert handler.dns_timeout == 120
        assert handler.max_retries == 5

    def test_prepare_http_validation_with_realistic_zerossl_data(self):
        """Test HTTP validation preparation with realistic ZeroSSL validation data."""
        # Arrange: Real ValidationHandler instance and realistic validation data
        handler = ValidationHandler()
        realistic_validation_data = {
            'example.com': {
                'file_validation_url_http': 'http://example.com/.well-known/pki-validation/A1B2C3D4E5F6G7H8.txt',
                'file_validation_content': ['A1B2C3D4E5F6G7H8', 'comodoca.com', '9I0J1K2L3M4N5O6P']
            },
            'www.example.com': {
                'file_validation_url_http': 'http://www.example.com/.well-known/pki-validation/B2C3D4E5F6G7H8I9.txt',
                'file_validation_content': ['B2C3D4E5F6G7H8I9', 'sectigo.com', '0P1Q2R3S4T5U6V7W']
            }
        }

        # Act: Call real method with realistic data - no mocking of business logic
        validation_files = handler.prepare_http_validation(realistic_validation_data)

        # Assert: Verify real method output structure and content
        assert len(validation_files) == 2

        # Verify first domain validation file
        example_file = next(vf for vf in validation_files if vf['domain'] == 'example.com')
        assert example_file['filename'] == 'A1B2C3D4E5F6G7H8.txt'
        assert example_file['content'] == ['A1B2C3D4E5F6G7H8', 'comodoca.com', '9I0J1K2L3M4N5O6P']
        assert example_file['url_path'] == '/.well-known/pki-validation/A1B2C3D4E5F6G7H8.txt'
        assert example_file['full_url'] == 'http://example.com/.well-known/pki-validation/A1B2C3D4E5F6G7H8.txt'

        # Verify second domain validation file
        www_file = next(vf for vf in validation_files if vf['domain'] == 'www.example.com')
        assert www_file['filename'] == 'B2C3D4E5F6G7H8I9.txt'
        assert www_file['content'] == ['B2C3D4E5F6G7H8I9', 'sectigo.com', '0P1Q2R3S4T5U6V7W']
        assert www_file['url_path'] == '/.well-known/pki-validation/B2C3D4E5F6G7H8I9.txt'
        assert www_file['full_url'] == 'http://www.example.com/.well-known/pki-validation/B2C3D4E5F6G7H8I9.txt'

    def test_extract_filename_from_validation_url(self):
        """Test filename extraction from ZeroSSL validation URLs."""
        # Arrange: Real ValidationHandler and realistic ZeroSSL validation URLs
        handler = ValidationHandler()
        test_cases = [
            ('http://example.com/.well-known/pki-validation/A1B2C3D4E5F6G7H8.txt', 'A1B2C3D4E5F6G7H8.txt'),
            ('https://secure-site.com/.well-known/pki-validation/F6G7H8I9J0K1L2M3.txt', 'F6G7H8I9J0K1L2M3.txt'),
            ('http://sub.domain.com/.well-known/pki-validation/Z9Y8X7W6V5U4T3S2.txt', 'Z9Y8X7W6V5U4T3S2.txt'),
            ('https://api.service.com/.well-known/pki-validation/M3N4O5P6Q7R8S9T0.txt', 'M3N4O5P6Q7R8S9T0.txt')
        ]

        # Act & Assert: Test real URL parsing logic for each case
        for validation_url, expected_filename in test_cases:
            # Call real private method - no mocking of internal logic
            actual_filename = handler._extract_filename_from_url(validation_url)
            assert actual_filename == expected_filename
            assert actual_filename.endswith('.txt')
            assert len(actual_filename) > 10  # ZeroSSL uses long filenames

    def test_construct_validation_file_paths(self):
        """Test construction of validation file paths for various web roots."""
        # Arrange: Real ValidationHandler instance
        handler = ValidationHandler()
        test_cases = [
            ('/var/www/html', '/.well-known/pki-validation/A1B2C3D4.txt'),
            ('/home/user/public_html', '/.well-known/pki-validation/E5F6G7H8.txt'),
            ('/opt/nginx/html', '/.well-known/pki-validation/I9J0K1L2.txt'),
            ('C:\\inetpub\\wwwroot', '/.well-known/pki-validation/M3N4O5P6.txt')
        ]

        # Act & Assert: Test real path construction logic
        for web_root, url_path in test_cases:
            full_path = handler._construct_file_path(web_root, url_path)
            expected_path = Path(web_root) / '.well-known' / 'pki-validation' / url_path.split('/')[-1]

            assert full_path == str(expected_path)
            assert '.well-known' in full_path
            assert 'pki-validation' in full_path
            assert full_path.endswith('.txt')

    def test_place_validation_files_in_filesystem(self, temp_directory):
        """Test placing validation files with realistic ZeroSSL content."""
        # Arrange: Real ValidationHandler and realistic ZeroSSL validation files
        handler = ValidationHandler()
        realistic_validation_files = [
            {
                'domain': 'example.com',
                'filename': 'A1B2C3D4E5F6G7H8.txt',
                'content': ['A1B2C3D4E5F6G7H8', 'comodoca.com', '9I0J1K2L3M4N5O6P'],
                'url_path': '/.well-known/pki-validation/A1B2C3D4E5F6G7H8.txt'
            },
            {
                'domain': 'www.example.com',
                'filename': 'B2C3D4E5F6G7H8I9.txt',
                'content': ['B2C3D4E5F6G7H8I9', 'sectigo.com', '0P1Q2R3S4T5U6V7W'],
                'url_path': '/.well-known/pki-validation/B2C3D4E5F6G7H8I9.txt'
            }
        ]

        # Act: Call real file placement method - tests actual filesystem logic
        result = handler.place_validation_files(realistic_validation_files, str(temp_directory))

        # Assert: Verify real file operations succeeded
        assert result['success'] is True
        assert result['error'] is None
        assert len(result['files_created']) == 2

        # Verify actual files created with correct content
        for file_info in result['files_created']:
            file_path = Path(file_info['path'])
            assert file_path.exists()
            assert file_path.is_file()

            # Verify file permissions (real filesystem operation)
            stat_info = file_path.stat()
            assert oct(stat_info.st_mode)[-3:] == '644'

            # Verify content matches expected format
            actual_content = file_path.read_text()
            original_file = next(vf for vf in realistic_validation_files if vf['filename'] == file_path.name)
            expected_content = '\n'.join(original_file['content'])
            assert actual_content == expected_content

        # Verify directory structure created correctly
        well_known_dir = temp_directory / '.well-known' / 'pki-validation'
        assert well_known_dir.exists()
        assert well_known_dir.is_dir()

    def test_place_validation_files_permission_error_handling(self, temp_directory, mocker):
        """Test real error handling when filesystem permissions fail."""
        # Arrange: Real ValidationHandler and validation files
        handler = ValidationHandler()
        validation_files = [
            {
                'domain': 'example.com',
                'filename': 'permission_test.txt',
                'content': ['test_content_line1', 'test_content_line2'],
                'url_path': '/.well-known/pki-validation/permission_test.txt'
            }
        ]

        # Mock only filesystem boundary - simulate permission denied at OS level
        mocker.patch('pathlib.Path.mkdir', side_effect=PermissionError("Permission denied"))

        # Act: Call real method with filesystem error - exercises real error handling
        result = handler.place_validation_files(validation_files, str(temp_directory))

        # Assert: Verify real error handling logic
        assert result['success'] is False
        assert 'permission denied' in result['error'].lower()
        assert result['files_created'] == []  # No files should be reported as created

    def test_verify_http_validation_successful_match(self, mocker):
        """Test HTTP validation verification with successful content match."""
        # Arrange: Real ValidationHandler and realistic validation scenario
        handler = ValidationHandler(http_timeout=45)
        validation_url = 'http://example.com/.well-known/pki-validation/A1B2C3D4E5F6G7H8.txt'
        expected_content = 'A1B2C3D4E5F6G7H8\ncomodoca.com\n9I0J1K2L3M4N5O6P'

        # Mock only HTTP boundary - simulate successful validation file fetch
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = expected_content
        mocker.patch('requests.get', return_value=mock_response)

        # Act: Call real verification method - exercises actual validation logic
        result = handler.verify_http_validation(validation_url, expected_content)

        # Assert: Verify real method response structure and logic
        assert result['accessible'] is True
        assert result['content_match'] is True
        assert result['status_code'] == 200
        assert result['error'] is None

        # Verify real HTTP call made with correct parameters
        requests_get_mock = mocker.patch('requests.get')
        handler.verify_http_validation(validation_url, expected_content)
        requests_get_mock.assert_called_with(validation_url, timeout=45)

    def test_verify_http_validation_error_scenarios(self, mocker):
        """Test HTTP validation verification with various error conditions."""
        # Arrange: Real ValidationHandler and realistic validation scenarios
        handler = ValidationHandler()
        validation_url = 'http://example.com/.well-known/pki-validation/B2C3D4E5F6G7H8I9.txt'
        expected_content = 'B2C3D4E5F6G7H8I9\nsectigo.com\n0P1Q2R3S4T5U6V7W'

        # Test scenarios: (status_code, response_text, expected_accessible, expected_match)
        test_scenarios = [
            (404, 'Not Found', False, False),
            (403, 'Forbidden', False, False),
            (500, 'Internal Server Error', False, False),
            (200, 'wrong_validation_content', True, False),  # Accessible but content mismatch
            (200, 'B2C3D4E5F6G7H8I9\nsectigo.com\nWRONG_TOKEN', True, False)  # Partial match
        ]

        for status_code, response_text, expected_accessible, expected_match in test_scenarios:
            # Mock only HTTP boundary - simulate various server responses
            mock_response = Mock()
            mock_response.status_code = status_code
            mock_response.text = response_text
            mocker.patch('requests.get', return_value=mock_response)

            # Act: Call real validation method - exercises actual error handling logic
            result = handler.verify_http_validation(validation_url, expected_content)

            # Assert: Verify real error detection and categorization
            assert result['accessible'] == expected_accessible
            assert result['content_match'] == expected_match
            assert result['status_code'] == status_code

            if not expected_accessible:
                assert 'not accessible' in result['error'].lower()

    def test_verify_http_validation_network_errors(self, mocker):
        """Test HTTP validation with realistic network error conditions."""
        # Arrange: Real ValidationHandler for network error testing
        handler = ValidationHandler(http_timeout=30)
        validation_url = 'http://unreachable.example.com/.well-known/pki-validation/C3D4E5F6G7H8I9J0.txt'
        expected_content = 'C3D4E5F6G7H8I9J0\ncomodoca.com\nvalidation_token'

        # Test different network error scenarios
        import requests.exceptions
        network_errors = [
            (requests.exceptions.Timeout(), 'timeout'),
            (requests.exceptions.ConnectionError(), 'connection failed'),
            (Exception('DNS resolution failed'), 'unexpected error')
        ]

        for exception, expected_error_type in network_errors:
            # Mock only HTTP boundary - simulate network-level errors
            mocker.patch('requests.get', side_effect=exception)

            # Act: Call real method - exercises actual network error handling
            result = handler.verify_http_validation(validation_url, expected_content)

            # Assert: Verify real error handling for network issues
            assert result['accessible'] is False
            assert result['content_match'] is False
            assert result['status_code'] is None
            assert expected_error_type in result['error'].lower()

    def test_prepare_dns_validation_with_realistic_cname_data(self):
        """Test DNS validation preparation with realistic ZeroSSL CNAME data."""
        # Arrange: Real ValidationHandler and realistic ZeroSSL DNS validation data
        handler = ValidationHandler()
        realistic_dns_validation = {
            'example.com': {
                'cname_validation_p1': 'F6G7H8I9J0K1L2M3.example.com',
                'cname_validation_p2': 'F6G7H8I9J0K1L2M3.N4O5P6Q7R8S9T0U1.V2W3X4Y5Z6A7B8C9.zerossl.com'
            },
            'www.example.com': {
                'cname_validation_p1': 'G7H8I9J0K1L2M3N4.www.example.com',
                'cname_validation_p2': 'G7H8I9J0K1L2M3N4.O5P6Q7R8S9T0U1V2.W3X4Y5Z6A7B8C9D0.zerossl.com'
            },
            'api.example.com': {
                'cname_validation_p1': 'H8I9J0K1L2M3N4O5.api.example.com',
                'cname_validation_p2': 'H8I9J0K1L2M3N4O5.P6Q7R8S9T0U1V2W3.X4Y5Z6A7B8C9D0E1.zerossl.com'
            }
        }

        # Act: Call real DNS preparation method - no mocking of business logic
        dns_records = handler.prepare_dns_validation(realistic_dns_validation)

        # Assert: Verify real method output structure and ZeroSSL CNAME format
        assert len(dns_records) == 3

        # Verify each DNS record has correct structure
        for record in dns_records:
            assert 'domain' in record
            assert 'record_name' in record
            assert 'record_type' in record
            assert 'record_value' in record
            assert record['record_type'] == 'CNAME'

            # Verify ZeroSSL CNAME format
            assert record['record_name'].endswith('.example.com')
            assert record['record_value'].endswith('.zerossl.com')
            assert len(record['record_name'].split('.')[0]) == 16  # ZeroSSL prefix length

        # Verify specific domain mappings
        example_record = next(r for r in dns_records if r['domain'] == 'example.com')
        assert example_record['record_name'] == 'F6G7H8I9J0K1L2M3.example.com'
        assert example_record['record_value'] == 'F6G7H8I9J0K1L2M3.N4O5P6Q7R8S9T0U1.V2W3X4Y5Z6A7B8C9.zerossl.com'

    def test_parse_dns_record_names_from_zerossl(self):
        """Test parsing of ZeroSSL DNS record names."""
        # Arrange: Real ValidationHandler and realistic ZeroSSL DNS record names
        handler = ValidationHandler()
        zerossl_record_names = [
            'F6G7H8I9J0K1L2M3.example.com',
            'G7H8I9J0K1L2M3N4.www.example.com',
            'H8I9J0K1L2M3N4O5.api.example.com',
            'I9J0K1L2M3N4O5P6.cdn.service.example.com'
        ]

        # Act & Assert: Test real DNS record name parsing logic
        for record_name in zerossl_record_names:
            # Call real private method - no mocking of parsing logic
            parsed_name = handler._parse_dns_record_name(record_name)

            # Verify parsing preserves ZeroSSL format
            assert parsed_name == record_name
            assert len(parsed_name.split('.')) >= 3  # At least token.domain.com
            assert len(parsed_name.split('.')[0]) == 16  # ZeroSSL token length

    def test_generate_dns_setup_instructions(self):
        """Test generation of user-friendly DNS setup instructions."""
        # Arrange: Real ValidationHandler and realistic ZeroSSL DNS records
        handler = ValidationHandler()
        realistic_dns_records = [
            {
                'domain': 'example.com',
                'record_name': 'F6G7H8I9J0K1L2M3.example.com',
                'record_type': 'CNAME',
                'record_value': 'F6G7H8I9J0K1L2M3.N4O5P6Q7R8S9T0U1.V2W3X4Y5Z6A7B8C9.zerossl.com'
            },
            {
                'domain': 'www.example.com',
                'record_name': 'G7H8I9J0K1L2M3N4.www.example.com',
                'record_type': 'CNAME',
                'record_value': 'G7H8I9J0K1L2M3N4.O5P6Q7R8S9T0U1V2.W3X4Y5Z6A7B8C9D0.zerossl.com'
            }
        ]

        # Act: Call real instruction generation method
        instructions = handler.generate_dns_instructions(realistic_dns_records)

        # Assert: Verify real instruction format and content
        assert 'records_to_create' in instructions
        assert len(instructions['records_to_create']) == 2
        assert instructions['records_to_create'] == realistic_dns_records

        assert 'instructions' in instructions
        assert isinstance(instructions['instructions'], str)

        # Verify instruction content includes ZeroSSL CNAME details
        instruction_text = instructions['instructions']
        assert 'CNAME' in instruction_text
        assert 'DNS Records to Create' in instruction_text
        assert 'example.com' in instruction_text
        assert 'www.example.com' in instruction_text
        assert 'zerossl.com' in instruction_text
        assert 'DNS propagation' in instruction_text

    def test_verify_dns_validation_successful_resolution(self, mocker):
        """Test DNS validation verification with successful CNAME resolution."""
        # Arrange: Real ValidationHandler and realistic ZeroSSL DNS validation
        handler = ValidationHandler(dns_timeout=90)
        record_name = 'F6G7H8I9J0K1L2M3.example.com'
        expected_value = 'F6G7H8I9J0K1L2M3.N4O5P6Q7R8S9T0U1.V2W3X4Y5Z6A7B8C9.zerossl.com'

        # Mock only DNS boundary - simulate successful DNS resolution
        mock_record = Mock()
        mock_record.to_text.return_value = f'{expected_value}.'  # DNS records end with .
        mock_resolver = Mock()
        mock_resolver.resolve.return_value = [mock_record]
        mocker.patch('dns.resolver.Resolver', return_value=mock_resolver)

        # Act: Call real DNS verification method - exercises actual validation logic
        result = handler.verify_dns_validation(record_name, expected_value)

        # Assert: Verify real method response for successful DNS validation
        assert result['record_exists'] is True
        assert result['value_match'] is True
        assert result['actual_values'] == [expected_value]
        assert result['error'] is None

        # Verify real DNS query parameters
        mock_resolver.resolve.assert_called_once_with(record_name, 'CNAME')
        assert mock_resolver.timeout == 90
        assert mock_resolver.lifetime == 90

    def test_verify_dns_validation_error_conditions(self, mocker):
        """Test DNS validation verification with various error conditions."""
        # Arrange: Real ValidationHandler for DNS error testing
        handler = ValidationHandler()
        record_name = 'G7H8I9J0K1L2M3N4.example.com'
        expected_value = 'G7H8I9J0K1L2M3N4.O5P6Q7R8S9T0U1V2.W3X4Y5Z6A7B8C9D0.zerossl.com'

        # Test Case 1: DNS record not found (NXDOMAIN)
        from dns.resolver import NXDOMAIN, NoAnswer
        mock_resolver_nxdomain = Mock()
        mock_resolver_nxdomain.resolve.side_effect = NXDOMAIN()
        mocker.patch('dns.resolver.Resolver', return_value=mock_resolver_nxdomain)

        # Act: Test NXDOMAIN handling
        result = handler.verify_dns_validation(record_name, expected_value)

        # Assert: Verify real NXDOMAIN error handling
        assert result['record_exists'] is False
        assert result['value_match'] is False
        assert 'not found' in result['error'].lower()
        assert result['actual_values'] == []

        # Test Case 2: No CNAME record found (NoAnswer)
        mock_resolver_no_answer = Mock()
        mock_resolver_no_answer.resolve.side_effect = NoAnswer()
        mocker.patch('dns.resolver.Resolver', return_value=mock_resolver_no_answer)

        result = handler.verify_dns_validation(record_name, expected_value)
        assert result['record_exists'] is False
        assert 'no cname record' in result['error'].lower()

        # Test Case 3: Wrong CNAME value
        mock_record_wrong = Mock()
        mock_record_wrong.to_text.return_value = 'WRONG_TOKEN.WRONG_SUFFIX.zerossl.com.'
        mock_resolver_wrong = Mock()
        mock_resolver_wrong.resolve.return_value = [mock_record_wrong]
        mocker.patch('dns.resolver.Resolver', return_value=mock_resolver_wrong)

        result = handler.verify_dns_validation(record_name, expected_value)
        assert result['record_exists'] is True
        assert result['value_match'] is False
        assert result['actual_values'] == ['WRONG_TOKEN.WRONG_SUFFIX.zerossl.com']

    def test_wildcard_domain_dns_validation_handling(self):
        """Test DNS validation preparation for wildcard domains."""
        # Arrange: Real ValidationHandler and wildcard domain validation data
        handler = ValidationHandler()
        wildcard_dns_data = {
            '*.example.com': {
                'cname_validation_p1': 'H8I9J0K1L2M3N4O5.example.com',
                'cname_validation_p2': 'H8I9J0K1L2M3N4O5.P6Q7R8S9T0U1V2W3.X4Y5Z6A7B8C9D0E1.zerossl.com'
            },
            '*.api.example.com': {
                'cname_validation_p1': 'I9J0K1L2M3N4O5P6.api.example.com',
                'cname_validation_p2': 'I9J0K1L2M3N4O5P6.Q7R8S9T0U1V2W3X4.Y5Z6A7B8C9D0E1F2.zerossl.com'
            }
        }

        # Act: Call real DNS preparation for wildcard domains
        dns_records = handler.prepare_dns_validation(wildcard_dns_data)

        # Assert: Verify real wildcard DNS record handling
        assert len(dns_records) == 2

        # Verify first wildcard domain
        wildcard_record = next(r for r in dns_records if r['domain'] == '*.example.com')
        assert wildcard_record['record_name'] == 'H8I9J0K1L2M3N4O5.example.com'
        assert wildcard_record['record_value'] == 'H8I9J0K1L2M3N4O5.P6Q7R8S9T0U1V2W3.X4Y5Z6A7B8C9D0E1.zerossl.com'
        assert wildcard_record['record_type'] == 'CNAME'

        # Verify second wildcard subdomain
        api_wildcard_record = next(r for r in dns_records if r['domain'] == '*.api.example.com')
        assert api_wildcard_record['record_name'] == 'I9J0K1L2M3N4O5P6.api.example.com'
        assert 'api.example.com' in api_wildcard_record['record_name']


    def test_suggest_optimal_validation_method(self):
        """Test automatic validation method selection based on domain types."""
        # Arrange: Real ValidationHandler for method selection testing
        handler = ValidationHandler()

        # Test Case 1: Regular domains - should suggest HTTP validation
        regular_domains = ['example.com', 'www.example.com', 'api.example.com']

        # Act: Call real method selection logic
        method = handler.suggest_validation_method(regular_domains)

        # Assert: HTTP validation recommended for regular domains
        assert method == 'HTTP_CSR_HASH'

        # Test Case 2: Wildcard domains present - should suggest DNS validation
        wildcard_domains = ['*.example.com', 'example.com', '*.api.example.com']

        # Act: Call real method selection with wildcard domains
        method = handler.suggest_validation_method(wildcard_domains)

        # Assert: DNS validation required for wildcard domains
        assert method == 'DNS_CSR_HASH'

        # Test Case 3: Mixed domain types - wildcard takes precedence
        mixed_domains = ['example.com', 'www.example.com', '*.subdomain.example.com']
        method = handler.suggest_validation_method(mixed_domains)
        assert method == 'DNS_CSR_HASH'

    def test_cleanup_validation_files_and_directories(self, temp_directory):
        """Test cleanup of validation files and empty directories."""
        # Arrange: Real ValidationHandler and validation files to clean up
        handler = ValidationHandler()
        validation_files = [
            {
                'domain': 'example.com',
                'filename': 'cleanup_A1B2C3D4.txt',
                'content': ['A1B2C3D4E5F6G7H8', 'comodoca.com', 'cleanup_token'],
                'url_path': '/.well-known/pki-validation/cleanup_A1B2C3D4.txt'
            },
            {
                'domain': 'www.example.com',
                'filename': 'cleanup_E5F6G7H8.txt',
                'content': ['E5F6G7H8I9J0K1L2', 'sectigo.com', 'cleanup_token_2'],
                'url_path': '/.well-known/pki-validation/cleanup_E5F6G7H8.txt'
            }
        ]

        # Act: Place files first, then test cleanup - real filesystem operations
        place_result = handler.place_validation_files(validation_files, str(temp_directory))
        assert place_result['success'] is True

        # Verify files actually created on filesystem
        created_files = place_result['files_created']
        for file_info in created_files:
            assert Path(file_info['path']).exists()

        # Act: Call real cleanup method - exercises actual file removal logic
        cleanup_result = handler.cleanup_validation_files(created_files)

        # Assert: Verify real cleanup results
        assert cleanup_result['success'] is True
        assert len(cleanup_result['files_removed']) == 2
        assert cleanup_result['errors'] == []

        # Verify files actually removed from filesystem
        for file_info in created_files:
            assert not Path(file_info['path']).exists()

        # Verify empty directories cleaned up (real directory cleanup logic)
        well_known_dir = temp_directory / '.well-known'
        pki_validation_dir = well_known_dir / 'pki-validation'

        # Directories should be removed if empty
        if well_known_dir.exists():
            assert not any(well_known_dir.iterdir())  # Should be empty if not removed

    def test_multiple_validation_operations_performance(self, mocker):
        """Test performance of multiple validation operations executed sequentially."""
        # Arrange: Real ValidationHandler for performance testing
        handler = ValidationHandler(http_timeout=10)  # Faster timeout for testing
        validation_scenarios = [
            (f'http://domain{i}.example.com/.well-known/pki-validation/token{i:02d}.txt', f'validation_content_{i}')
            for i in range(8)
        ]

        # Mock only HTTP boundary - simulate successful responses
        mock_response = Mock()
        mock_response.status_code = 200
        mocker.patch('requests.get', return_value=mock_response)

        # Act: Execute multiple validations and measure performance
        start_time = time.time()
        results = []

        for validation_url, expected_content in validation_scenarios:
            mock_response.text = expected_content  # Set expected content for each request
            result = handler.verify_http_validation(validation_url, expected_content)
            results.append(result)

        execution_time = time.time() - start_time

        # Assert: Verify all operations completed successfully within time limits
        assert len(results) == 8
        assert all(r['accessible'] is True for r in results)
        assert all(r['content_match'] is True for r in results)
        assert all(r['status_code'] == 200 for r in results)

        # Performance requirement: Each validation should be fast
        assert execution_time < 5.0  # Total time should be reasonable
        average_time_per_validation = execution_time / len(validation_scenarios)
        assert average_time_per_validation < 1.0  # Each validation should be quick

    def test_aggregate_validation_errors_from_multiple_domains(self):
        """Test aggregation of validation errors from multiple domain failures."""
        # Arrange: Real ValidationHandler and realistic validation errors
        handler = ValidationHandler()
        realistic_validation_errors = [
            {'domain': 'example.com', 'error': 'HTTP validation file not accessible (404)'},
            {'domain': 'www.example.com', 'error': 'DNS CNAME record not found (NXDOMAIN)'},
            {'domain': 'api.example.com', 'error': 'Connection timeout during HTTP validation'},
            {'domain': '*.subdomain.example.com', 'error': 'DNS CNAME value mismatch'}
        ]

        # Act: Call real error aggregation method - no mocking of business logic
        aggregated_error = handler.aggregate_validation_errors(realistic_validation_errors)

        # Assert: Verify real error aggregation structure and content
        assert 'Multiple domains failed validation' in aggregated_error['message']
        assert '4 errors' in aggregated_error['message']
        assert aggregated_error['failed_count'] == 4
        assert len(aggregated_error['domain_errors']) == 4
        assert aggregated_error['domain_errors'] == realistic_validation_errors

        # Verify summary format includes all domains and errors
        assert len(aggregated_error['summary']) == 4
        assert 'example.com: HTTP validation file not accessible (404)' in aggregated_error['summary']
        assert 'www.example.com: DNS CNAME record not found (NXDOMAIN)' in aggregated_error['summary']
        assert 'api.example.com: Connection timeout during HTTP validation' in aggregated_error['summary']
        assert '*.subdomain.example.com: DNS CNAME value mismatch' in aggregated_error['summary']

    def test_prepare_http_validation_with_malformed_data(self):
        """Test HTTP validation preparation error handling with malformed ZeroSSL data."""
        # Arrange: Real ValidationHandler and malformed validation data
        handler = ValidationHandler()

        # Test Case 1: Missing HTTP validation URL
        malformed_data_no_url = {
            'example.com': {
                'file_validation_content': ['A1B2C3D4E5F6G7H8', 'comodoca.com', 'token']
                # Missing 'file_validation_url_http'
            }
        }

        # Act & Assert: Verify real exception handling for missing URL
        with pytest.raises(ZeroSSLValidationError) as exc_info:
            handler.prepare_http_validation(malformed_data_no_url)

        assert 'Missing HTTP validation URL for domain: example.com' in str(exc_info.value)
        assert exc_info.value.domain == 'example.com'
        assert exc_info.value.validation_method == 'HTTP_CSR_HASH'

        # Test Case 2: Missing validation content
        malformed_data_no_content = {
            'www.example.com': {
                'file_validation_url_http': 'http://www.example.com/.well-known/pki-validation/test.txt'
                # Missing 'file_validation_content'
            }
        }

        # Act & Assert: Verify real exception handling for missing content
        with pytest.raises(ZeroSSLValidationError) as exc_info:
            handler.prepare_http_validation(malformed_data_no_content)

        assert 'Missing validation content for domain: www.example.com' in str(exc_info.value)
        assert exc_info.value.domain == 'www.example.com'

    def test_prepare_dns_validation_with_malformed_cname_data(self):
        """Test DNS validation preparation error handling with malformed CNAME data."""
        # Arrange: Real ValidationHandler for DNS error testing
        handler = ValidationHandler()

        # Test Case 1: Missing CNAME record name
        malformed_dns_no_p1 = {
            'example.com': {
                'cname_validation_p2': 'F6G7H8I9J0K1L2M3.N4O5P6Q7R8S9T0U1.V2W3X4Y5Z6A7B8C9.zerossl.com'
                # Missing 'cname_validation_p1'
            }
        }

        # Act & Assert: Verify real exception handling for missing CNAME name
        with pytest.raises(ZeroSSLValidationError) as exc_info:
            handler.prepare_dns_validation(malformed_dns_no_p1)

        assert 'Missing DNS CNAME record name for domain: example.com' in str(exc_info.value)
        assert exc_info.value.validation_method == 'DNS_CSR_HASH'

        # Test Case 2: Missing CNAME record value
        malformed_dns_no_p2 = {
            'www.example.com': {
                'cname_validation_p1': 'G7H8I9J0K1L2M3N4.www.example.com'
                # Missing 'cname_validation_p2'
            }
        }

        # Act & Assert: Verify real exception handling for missing CNAME value
        with pytest.raises(ZeroSSLValidationError) as exc_info:
            handler.prepare_dns_validation(malformed_dns_no_p2)

        assert 'Missing DNS CNAME record value for domain: www.example.com' in str(exc_info.value)
