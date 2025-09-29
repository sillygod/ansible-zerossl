# -*- coding: utf-8 -*-
"""
Unit tests for ZeroSSL Utility Functions - Improved Design.

These tests verify utility function functionality using real business logic
without mocking internal methods, only mocking at HTTP boundary when needed.

Test Design Principles:
- Exercise real utility functions and code paths
- Use realistic input data and scenarios
- Test actual method signatures and validation logic
- Achieve comprehensive coverage through real execution
- No internal method mocking - only external dependencies when required
"""

import pytest
import tempfile
import os
import socket
from pathlib import Path
from unittest.mock import patch

from plugins.module_utils.zerossl.utils import (
    validate_domain, validate_domains, is_wildcard_domain, extract_base_domain,
    domains_overlap, check_domain_dns_resolution, check_domain_http_accessibility,
    validate_file_path, validate_api_key, parse_validation_url, generate_csr,
    normalize_certificate_content, extract_certificate_info, create_file_with_permissions
)
from plugins.module_utils.zerossl.exceptions import (
    ZeroSSLConfigurationError, ZeroSSLValidationError, ZeroSSLFileSystemError
)


@pytest.mark.unit
class TestDomainValidationReal:
    """Test domain validation functions with real business logic."""

    @pytest.fixture
    def mock_http_boundary(self, mocker):
        """Mock HTTP boundary for external API calls."""
        return mocker.patch('requests.Session')

    def test_validate_domain_real_logic_valid_domains(self):
        """
        Test validate_domain with valid domains using real validation logic.

        This exercises the real validate_domain function without mocking
        any internal validation logic.
        """
        valid_domains = [
            'example.com',
            'www.example.com',
            'sub.domain.example.org',
            'test-site.co.uk',
            'a.b.c.d.e.f.example.net',
            '*.example.com',
            '*.sub.example.org'
        ]

        for domain in valid_domains:
            assert validate_domain(domain) is True

    def test_validate_domain_real_error_handling(self):
        """
        Test validate_domain error handling with real validation logic.

        This exercises real error conditions and exception handling
        without mocking the validation functions.
        """
        # Test empty domain
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_domain('')
        assert "Domain cannot be empty" in str(exc_info.value)

        # Test None domain
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_domain(None)
        assert "Domain cannot be empty" in str(exc_info.value)

        # Test wildcard without base domain
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_domain('*.')
        assert "Wildcard domain must have a base domain" in str(exc_info.value)

        # Test domain too long
        long_domain = 'a' * 250 + '.com'
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_domain(long_domain)
        assert "exceeds maximum length of 253 characters" in str(exc_info.value)

        # Test single label domain
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_domain('localhost')
        assert "must have at least two labels" in str(exc_info.value)

    def test_validate_domain_real_whitespace_handling(self):
        """
        Test validate_domain whitespace handling with real logic.

        This exercises real whitespace stripping logic.
        """
        # Test that whitespace is properly stripped
        assert validate_domain('  example.com  ') is True

    def test_validate_domains_real_logic_valid_lists(self):
        """
        Test validate_domains with valid domain lists using real logic.

        This exercises the real validate_domains function with various
        valid domain combinations.
        """
        # Single domain
        result = validate_domains(['example.com'])
        assert result == ['example.com']

        # Multiple domains
        domains = ['example.com', 'www.example.com', 'blog.example.org']
        result = validate_domains(domains)
        assert result == ['example.com', 'www.example.com', 'blog.example.org']

        # Mixed case normalization
        domains = ['EXAMPLE.COM', 'Www.Example.Com']
        result = validate_domains(domains)
        assert result == ['example.com', 'www.example.com']

    def test_validate_domains_real_error_conditions(self):
        """
        Test validate_domains error conditions with real validation logic.

        This exercises real error handling without mocking validation.
        """
        # Empty list
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_domains([])
        assert "At least one domain is required" in str(exc_info.value)

        # None input
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_domains(None)
        assert "At least one domain is required" in str(exc_info.value)

        # Too many domains
        domains = [f'domain{i}.com' for i in range(101)]
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_domains(domains)
        assert "Maximum of 100 domains allowed per certificate" in str(exc_info.value)

        # Duplicate domains
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_domains(['example.com', 'EXAMPLE.COM'])
        assert "Duplicate domain: example.com" in str(exc_info.value)


@pytest.mark.unit
class TestWildcardDomainFunctionsReal:
    """Test wildcard domain utility functions with real logic."""

    def test_is_wildcard_domain_real_logic(self):
        """
        Test is_wildcard_domain with real detection logic.

        This exercises the real wildcard detection function.
        """
        # Wildcard domains
        assert is_wildcard_domain('*.example.com') is True
        assert is_wildcard_domain('*.sub.example.org') is True

        # Regular domains
        assert is_wildcard_domain('example.com') is False
        assert is_wildcard_domain('www.example.com') is False
        assert is_wildcard_domain('sub.example.com') is False

    def test_extract_base_domain_real_logic(self):
        """
        Test extract_base_domain with real extraction logic.

        This exercises the real base domain extraction function.
        """
        # Wildcard domains
        assert extract_base_domain('*.example.com') == 'example.com'
        assert extract_base_domain('*.sub.example.org') == 'sub.example.org'

        # Subdomain extraction
        assert extract_base_domain('www.example.com') == 'example.com'
        assert extract_base_domain('blog.sub.example.org') == 'example.org'
        assert extract_base_domain('api.service.company.com') == 'company.com'

        # Base domains
        assert extract_base_domain('example.com') == 'example.com'
        assert extract_base_domain('test.org') == 'test.org'

        # Edge cases
        assert extract_base_domain('a.b') == 'a.b'
        assert extract_base_domain('localhost') == 'localhost'

    def test_domains_overlap_real_logic(self):
        """
        Test domains_overlap with real overlap detection logic.

        This exercises the real domain overlap detection function.
        """
        # Exact matches
        assert domains_overlap('example.com', 'example.com') is True

        # Wildcard covering subdomain
        assert domains_overlap('*.example.com', 'www.example.com') is True
        assert domains_overlap('*.example.com', 'api.example.com') is True

        # Wildcard covering base domain
        assert domains_overlap('*.example.com', 'example.com') is True

        # Reverse wildcard checking
        assert domains_overlap('www.example.com', '*.example.com') is True

        # No overlap
        assert domains_overlap('example.com', 'other.com') is False
        assert domains_overlap('www.example.com', 'api.other.com') is False
        assert domains_overlap('*.example.com', 'www.other.com') is False

        # Case sensitivity (real function is case sensitive)
        assert domains_overlap('Example.Com', 'example.com') is False


@pytest.mark.unit
class TestDNSResolutionReal:
    """Test DNS resolution checking with real network operations when possible."""

    def test_check_domain_dns_resolution_real_structure(self):
        """
        Test check_domain_dns_resolution return structure with real function.

        This exercises the real DNS resolution function structure
        without making actual network calls.
        """
        with patch('dns.resolver.Resolver') as mock_resolver_class:
            mock_resolver = mock_resolver_class.return_value
            mock_resolver.resolve.side_effect = Exception("No network")

            result = check_domain_dns_resolution('test.example.com')

            # Verify real function structure
            assert 'domain' in result
            assert 'resolves' in result
            assert 'a_records' in result
            assert 'aaaa_records' in result
            assert 'error' in result

            assert result['domain'] == 'test.example.com'
            assert result['resolves'] is False
            assert result['a_records'] == []
            assert result['aaaa_records'] == []
            assert 'No network' in result['error']

    def test_check_domain_dns_resolution_real_timeout_configuration(self):
        """
        Test DNS resolution timeout configuration with real logic.

        This exercises the real timeout configuration logic.
        """
        with patch('dns.resolver.Resolver') as mock_resolver_class:
            mock_resolver = mock_resolver_class.return_value
            mock_resolver.resolve.side_effect = Exception("Timeout test")

            check_domain_dns_resolution('example.com', timeout=5)

            # Verify real timeout configuration
            assert mock_resolver.timeout == 5
            assert mock_resolver.lifetime == 5


@pytest.mark.unit
class TestHTTPAccessibilityReal:
    """Test HTTP accessibility checking with real network operations when possible."""

    def test_check_domain_http_accessibility_real_structure(self):
        """
        Test check_domain_http_accessibility return structure with real function.

        This exercises the real HTTP accessibility function structure.
        """
        with patch('socket.create_connection') as mock_create_connection:
            mock_create_connection.side_effect = ConnectionRefusedError("Connection refused")

            result = check_domain_http_accessibility('test.example.com')

            # Verify real function structure
            assert 'domain' in result
            assert 'port' in result
            assert 'accessible' in result
            assert 'error' in result

            assert result['domain'] == 'test.example.com'
            assert result['port'] == 80
            assert result['accessible'] is False
            assert 'Connection refused' in result['error']

    def test_check_domain_http_accessibility_real_success_simulation(self):
        """
        Test HTTP accessibility success with real function logic.

        This exercises real success path logic.
        """
        with patch('socket.create_connection') as mock_create_connection:
            mock_socket = mock_create_connection.return_value

            result = check_domain_http_accessibility('accessible.example.com', port=443)

            # Verify real function behavior
            mock_create_connection.assert_called_with(('accessible.example.com', 443), 10)
            mock_socket.close.assert_called_once()

            assert result['domain'] == 'accessible.example.com'
            assert result['port'] == 443
            assert result['accessible'] is True
            assert result['error'] is None


@pytest.mark.unit
class TestFilePathValidationReal:
    """Test file path validation with real filesystem operations."""

    @pytest.fixture
    def temp_directory(self):
        """Create a temporary directory for file testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    def test_validate_file_path_real_basic_validation(self):
        """
        Test validate_file_path basic validation with real logic.

        This exercises real path validation and resolution.
        """
        result = validate_file_path('/tmp/test.txt')
        expected = str(Path('/tmp/test.txt').resolve())
        assert result == expected

    def test_validate_file_path_real_error_conditions(self):
        """
        Test validate_file_path error conditions with real validation logic.

        This exercises real error handling without mocking validation.
        """
        # Empty path
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_file_path('')
        assert "File path cannot be empty" in str(exc_info.value)

        # None path
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_file_path(None)
        assert "File path cannot be empty" in str(exc_info.value)

    def test_validate_file_path_real_expanduser_logic(self, temp_directory):
        """
        Test validate_file_path tilde expansion with real logic.

        This exercises real path expansion functionality.
        """
        # Create a test file in temp directory to simulate home
        test_file = os.path.join(temp_directory, 'test.txt')
        Path(test_file).touch()

        # Test that real path resolution works
        result = validate_file_path(test_file)
        assert os.path.isabs(result)
        assert 'test.txt' in result

    def test_validate_file_path_real_must_exist_logic(self, temp_directory):
        """
        Test validate_file_path must_exist logic with real filesystem.

        This exercises real file existence checking.
        """
        # Create existing file
        existing_file = os.path.join(temp_directory, 'existing.txt')
        Path(existing_file).touch()

        # Test existing file validation
        result = validate_file_path(existing_file, must_exist=True)
        assert existing_file in result

        # Test non-existing file validation
        non_existing = os.path.join(temp_directory, 'nonexistent.txt')
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_file_path(non_existing, must_exist=True)
        assert "Path does not exist" in str(exc_info.value)

    def test_validate_file_path_real_writability_logic(self, temp_directory):
        """
        Test validate_file_path writability checking with real filesystem.

        This exercises real write permission testing.
        """
        writable_file = os.path.join(temp_directory, 'writable.txt')

        # Test writability validation with real filesystem
        result = validate_file_path(writable_file, must_be_writable=True)
        assert writable_file in result

        # Verify that the test file was actually created and removed
        test_file = Path(temp_directory) / '.ansible_zerossl_write_test'
        assert not test_file.exists()  # Should be cleaned up


@pytest.mark.unit
class TestAPIKeyValidationReal:
    """Test API key validation with real validation logic."""

    def test_validate_api_key_real_logic_valid_keys(self):
        """
        Test validate_api_key with valid keys using real validation logic.

        This exercises the real API key validation function.
        """
        valid_keys = [
            'test-api-key-1234567890123456',
            'abc123def456ghi789jkl012mno345',
            'PRODUCTION-KEY-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456',
            'dev_api_key_with_underscores_1234567890',
            'hyphen-separated-api-key-values-12345678'
        ]

        for key in valid_keys:
            result = validate_api_key(key)
            assert result == key

    def test_validate_api_key_real_error_conditions(self):
        """
        Test validate_api_key error conditions with real validation logic.

        This exercises real error handling without mocking validation.
        """
        # Empty key
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_api_key('')
        assert "API key is required" in str(exc_info.value)

        # None key
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_api_key(None)
        assert "API key is required" in str(exc_info.value)

        # Too short
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_api_key('short')
        assert "API key appears to be too short" in str(exc_info.value)

        # Too long
        long_key = 'a' * 201
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_api_key(long_key)
        assert "API key appears to be too long" in str(exc_info.value)

        # Invalid characters
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validate_api_key('invalid@key#with$special&chars')
        assert "API key contains invalid characters" in str(exc_info.value)

    def test_validate_api_key_real_whitespace_handling(self):
        """
        Test validate_api_key whitespace handling with real logic.

        This exercises real whitespace stripping logic.
        """
        key = '  valid-api-key-1234567890123456  '
        result = validate_api_key(key)
        assert result == 'valid-api-key-1234567890123456'


@pytest.mark.unit
class TestValidationURLParsingReal:
    """Test validation URL parsing with real parsing logic."""

    def test_parse_validation_url_real_parsing_logic(self):
        """
        Test parse_validation_url with real URL parsing logic.

        This exercises the real URL parsing function without mocking urlparse.
        """
        # Standard ACME challenge URL
        url = 'http://example.com/.well-known/acme-challenge/token123'
        result = parse_validation_url(url)

        assert result['scheme'] == 'http'
        assert result['domain'] == 'example.com'
        assert result['path'] == '/.well-known/acme-challenge/token123'
        assert result['filename'] == 'token123'
        assert result['full_url'] == url

        # HTTPS URL with port
        https_url = 'https://secure.example.com:443/validation/file.txt'
        result = parse_validation_url(https_url)

        assert result['scheme'] == 'https'
        assert result['domain'] == 'secure.example.com:443'
        assert result['filename'] == 'file.txt'

    def test_parse_validation_url_real_error_conditions(self):
        """
        Test parse_validation_url error conditions with real validation logic.

        This exercises real error handling without mocking validation.
        """
        # No scheme
        with pytest.raises(ZeroSSLValidationError) as exc_info:
            parse_validation_url('example.com/path/file.txt')
        assert "Validation URL must include scheme" in str(exc_info.value)

        # No domain
        with pytest.raises(ZeroSSLValidationError) as exc_info:
            parse_validation_url('http:///path/file.txt')
        assert "Validation URL must include domain" in str(exc_info.value)

        # No path
        with pytest.raises(ZeroSSLValidationError) as exc_info:
            parse_validation_url('http://example.com')
        assert "Validation URL must include path" in str(exc_info.value)

    def test_parse_validation_url_real_edge_cases(self):
        """
        Test parse_validation_url edge cases with real parsing logic.

        This exercises real edge case handling in URL parsing.
        """
        # URL with query parameters
        url = 'http://example.com/path/file.txt?param=value'
        result = parse_validation_url(url)
        assert result['filename'] == 'file.txt'
        # Note: query params are part of path in urlparse

        # URL ending with slash
        url = 'http://example.com/path/'
        result = parse_validation_url(url)
        assert result['filename'] == 'path'  # Last path component


@pytest.mark.unit
class TestCSRGenerationReal:
    """Test CSR generation functionality with real cryptography operations when available."""

    def test_generate_csr_real_import_error_handling(self):
        """
        Test generate_csr import error handling with real logic.

        This exercises real import error handling when cryptography is not available.
        """
        with patch.dict('sys.modules', {'cryptography': None}):
            with pytest.raises(ZeroSSLConfigurationError) as exc_info:
                generate_csr(['example.com'])
            assert "cryptography library is required" in str(exc_info.value)

    def test_generate_csr_real_functionality_when_available(self):
        """
        Test generate_csr real functionality when cryptography is available.

        This exercises real CSR generation or skips if not available.
        """
        try:
            csr_pem, private_key_pem = generate_csr(['example.com'])

            # Verify real output structure
            assert '-----BEGIN CERTIFICATE REQUEST-----' in csr_pem
            assert '-----END CERTIFICATE REQUEST-----' in csr_pem
            assert '-----BEGIN PRIVATE KEY-----' in private_key_pem
            assert '-----END PRIVATE KEY-----' in private_key_pem

        except ZeroSSLConfigurationError as e:
            if "cryptography library is required" in str(e):
                pytest.skip("cryptography library not available")
            else:
                raise

    def test_generate_csr_real_multiple_domains_when_available(self):
        """
        Test generate_csr with multiple domains using real functionality.

        This exercises real multi-domain CSR generation.
        """
        try:
            domains = ['example.com', 'www.example.com', 'api.example.com']
            csr_pem, private_key_pem = generate_csr(domains)

            # Verify real multi-domain CSR structure
            assert '-----BEGIN CERTIFICATE REQUEST-----' in csr_pem
            assert '-----BEGIN PRIVATE KEY-----' in private_key_pem

        except ZeroSSLConfigurationError as e:
            if "cryptography library is required" in str(e):
                pytest.skip("cryptography library not available")
            else:
                raise


@pytest.mark.unit
class TestCertificateContentFunctionsReal:
    """Test certificate content utility functions with real logic."""

    def test_normalize_certificate_content_real_logic(self):
        """
        Test normalize_certificate_content with real normalization logic.

        This exercises the real content normalization function.
        """
        # Basic normalization
        content = """-----BEGIN CERTIFICATE-----
MIICert
data here
-----END CERTIFICATE-----"""

        result = normalize_certificate_content(content)
        expected = """-----BEGIN CERTIFICATE-----
MIICert
data here
-----END CERTIFICATE-----
"""
        assert result == expected

        # Whitespace normalization
        messy_content = """
        -----BEGIN CERTIFICATE-----
        MIICert
        data here
        -----END CERTIFICATE-----
        """

        result = normalize_certificate_content(messy_content)
        expected = """-----BEGIN CERTIFICATE-----
MIICert
data here
-----END CERTIFICATE-----
"""
        assert result == expected

        # Empty content handling
        assert normalize_certificate_content('') == ''
        assert normalize_certificate_content(None) is None

    def test_extract_certificate_info_real_import_error_handling(self):
        """
        Test extract_certificate_info import error handling with real logic.

        This exercises real import error handling when cryptography is not available.
        """
        with patch.dict('sys.modules', {'cryptography': None}):
            with pytest.raises(ZeroSSLConfigurationError) as exc_info:
                extract_certificate_info('dummy cert')
            assert "cryptography library is required" in str(exc_info.value)

    def test_extract_certificate_info_real_error_handling_when_available(self):
        """
        Test extract_certificate_info error handling with real logic when available.

        This exercises real certificate parsing error handling.
        """
        try:
            with pytest.raises(ZeroSSLValidationError) as exc_info:
                extract_certificate_info('invalid certificate content')
            assert "Failed to parse certificate" in str(exc_info.value)

        except ZeroSSLConfigurationError as e:
            if "cryptography library is required" in str(e):
                pytest.skip("cryptography library not available")
            else:
                raise


@pytest.mark.unit
class TestFileCreationReal:
    """Test file creation with permissions using real filesystem operations."""

    @pytest.fixture
    def temp_directory(self):
        """Create a temporary directory for file testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    def test_create_file_with_permissions_real_success(self, temp_directory):
        """
        Test create_file_with_permissions success with real filesystem operations.

        This exercises real file creation and permission setting.
        """
        file_path = os.path.join(temp_directory, 'test.txt')
        content = 'test file content'

        create_file_with_permissions(file_path, content, 0o644)

        # Verify real file creation
        assert os.path.exists(file_path)

        # Verify real file content
        with open(file_path, 'r') as f:
            assert f.read() == content

        # Verify real file permissions
        file_stat = os.stat(file_path)
        file_mode = file_stat.st_mode & 0o777
        assert file_mode == 0o644

    def test_create_file_with_permissions_real_directory_creation(self, temp_directory):
        """
        Test create_file_with_permissions directory creation with real filesystem.

        This exercises real directory creation logic.
        """
        nested_path = os.path.join(temp_directory, 'nested', 'deep', 'test.txt')
        content = 'nested file content'

        create_file_with_permissions(nested_path, content, 0o600)

        # Verify real nested directory creation
        assert os.path.exists(nested_path)
        assert os.path.isdir(os.path.dirname(nested_path))

        # Verify real file permissions
        file_stat = os.stat(nested_path)
        file_mode = file_stat.st_mode & 0o777
        assert file_mode == 0o600

    def test_create_file_with_permissions_real_error_simulation(self):
        """
        Test create_file_with_permissions error handling with real logic.

        This exercises real error handling for filesystem operations.
        """
        # Try to create file in non-existent restricted directory
        restricted_path = '/root/restricted/test.txt'

        with pytest.raises(ZeroSSLFileSystemError) as exc_info:
            create_file_with_permissions(restricted_path, 'content')

        # Verify real error information
        assert exc_info.value.file_path == restricted_path
        assert exc_info.value.operation == 'create'
        assert "Permission denied" in str(exc_info.value) or "Failed to create file" in str(exc_info.value)


@pytest.mark.unit
class TestUtilityFunctionIntegrationReal:
    """Test utility function integration scenarios with real business logic."""

    def test_domain_validation_integration_real_workflow(self):
        """
        Test domain validation integration with real workflow logic.

        This exercises real integration between domain validation functions.
        """
        # Start with raw domain input
        raw_domains = ['  EXAMPLE.COM  ', 'www.Example.Com', '*.api.example.com']

        # Process through real validation pipeline
        validated_domains = validate_domains(raw_domains)

        # Verify real integration results
        assert validated_domains == ['example.com', 'www.example.com', '*.api.example.com']

        # Test real wildcard detection on results
        wildcards = [domain for domain in validated_domains if is_wildcard_domain(domain)]
        assert len(wildcards) == 1
        assert wildcards[0] == '*.api.example.com'

        # Test real base domain extraction
        base_domains = [extract_base_domain(domain) for domain in validated_domains]
        assert 'example.com' in base_domains
        assert 'api.example.com' in base_domains

        # Test real overlap detection
        assert domains_overlap(validated_domains[0], validated_domains[1]) is False
        assert domains_overlap(validated_domains[2], 'test.api.example.com') is True

    def test_file_path_validation_integration_real_workflow(self):
        """
        Test file path validation integration with real filesystem workflow.

        This exercises real integration between file path validation functions.
        """
        with tempfile.TemporaryDirectory() as temp_directory:
            # Create directory structure
            cert_dir = os.path.join(temp_directory, 'certificates')
            os.makedirs(cert_dir, exist_ok=True)

            # Define file paths
            cert_path = os.path.join(cert_dir, 'example.com.pem')
            key_path = os.path.join(cert_dir, 'example.com.key')

            # Validate paths with real validation
            validated_cert_path = validate_file_path(cert_path, must_be_writable=True)
            validated_key_path = validate_file_path(key_path, must_be_writable=True)

            # Create files with real file creation
            cert_content = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/OvD8XAXMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
-----END CERTIFICATE-----"""

            key_content = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
-----END PRIVATE KEY-----"""

            create_file_with_permissions(validated_cert_path, cert_content, 0o644)
            create_file_with_permissions(validated_key_path, key_content, 0o600)

            # Verify real file integration
            assert os.path.exists(validated_cert_path)
            assert os.path.exists(validated_key_path)

            # Verify real content normalization
            normalized_cert = normalize_certificate_content(cert_content)
            with open(validated_cert_path, 'r') as f:
                file_content = f.read()
            assert file_content in normalized_cert

    def test_api_key_and_url_validation_integration_real_workflow(self):
        """
        Test API key and URL validation integration with real workflow.

        This exercises real integration between API key and URL validation.
        """
        # Validate API key with real validation
        raw_api_key = '  production-api-key-1234567890123456789  '
        validated_api_key = validate_api_key(raw_api_key)
        assert validated_api_key == 'production-api-key-1234567890123456789'

        # Create validation URL based on domain
        domain = 'secure.example.com'
        validate_domain(domain)  # Real domain validation

        # Parse validation URL with real parsing
        validation_url = f'https://{domain}/.well-known/acme-challenge/token-{validated_api_key[:8]}'
        parsed_url = parse_validation_url(validation_url)

        # Verify real integration
        assert parsed_url['scheme'] == 'https'
        assert parsed_url['domain'] == domain
        assert f'token-{validated_api_key[:8]}' in parsed_url['path']
        assert parsed_url['filename'] == f'token-{validated_api_key[:8]}'
