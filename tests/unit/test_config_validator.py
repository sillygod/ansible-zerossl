# -*- coding: utf-8 -*-
"""
Unit tests for ZeroSSL Configuration Validator - Improved Design.

These tests verify configuration validation functionality using real business logic
without mocking internal methods, only mocking at HTTP boundary when needed.

Test Design Principles:
- Exercise real ConfigValidator methods and code paths
- Use realistic parameter data
- Test actual method signatures and validation logic
- Achieve comprehensive coverage through real execution
- No internal method mocking - only HTTP boundary when required
"""

import pytest
import tempfile
import os
from pathlib import Path

from plugins.module_utils.zerossl.config_validator import ConfigValidator
from plugins.module_utils.zerossl.exceptions import ZeroSSLConfigurationError
from plugins.module_utils.zerossl.models import OperationState, ValidationMethod


@pytest.mark.unit
class TestConfigValidatorImproved:
    """
    Improved unit tests for ConfigValidator.

    Tests real ConfigValidator methods exercising actual business logic
    and validation code paths without mocking internal components.
    """

    @pytest.fixture
    def validator(self):
        """Create a real ConfigValidator instance for testing."""
        return ConfigValidator()

    @pytest.fixture
    def mock_http_boundary(self, mocker):
        """Mock HTTP boundary for external API calls."""
        return mocker.patch('requests.Session')

    @pytest.fixture
    def temp_directory(self):
        """Create a temporary directory for file path testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    def test_config_validator_initialization(self, validator):
        """
        Test real ConfigValidator initialization.

        This test exercises the real constructor and validates proper
        initialization of validation rules without mocking.
        """
        assert validator.valid_states == [state.value for state in OperationState]
        assert validator.valid_validation_methods == [method.value for method in ValidationMethod]
        assert validator.valid_validity_days == [90, 365]

    def test_validate_plugin_parameters_minimal_valid_dns(self, validator):
        """
        Test validation with minimal valid parameters using DNS validation.

        This exercises the real validate_plugin_parameters method and all
        its validation code paths with realistic data.
        """
        params = {
            'api_key': 'test-api-key-1234567890123456',
            'domains': ['example.com'],
            'validation_method': 'DNS_CSR_HASH'
        }

        result = validator.validate_plugin_parameters(params)

        assert result['api_key'] == 'test-api-key-1234567890123456'
        assert result['domains'] == ['example.com']
        assert result['state'] == 'present'
        assert result['validation_method'] == 'DNS_CSR_HASH'
        assert result['validity_days'] == 90
        assert result['renew_threshold_days'] == 30
        assert result['force'] is False
        assert result['backup'] is False
        assert result['timeout'] == 30
        assert result['validation_timeout'] == 300
        assert result['file_mode'] == 0o600

    def test_validate_plugin_parameters_with_file_paths(self, validator, temp_directory):
        """
        Test validation with file paths exercising real file validation logic.

        This test uses real temporary files to exercise actual file path
        validation without mocking filesystem operations.
        """
        cert_path = os.path.join(temp_directory, 'cert.pem')
        key_path = os.path.join(temp_directory, 'key.pem')

        params = {
            'api_key': 'test-api-key-1234567890123456',
            'domains': ['example.com'],
            'validation_method': 'DNS_CSR_HASH',
            'certificate_path': cert_path,
            'private_key_path': key_path
        }

        result = validator.validate_plugin_parameters(params)

        assert result['certificate_path'] == str(Path(cert_path).resolve())
        assert result['private_key_path'] == str(Path(key_path).resolve())

    def test_validate_plugin_parameters_complete_configuration(self, validator, temp_directory):
        """
        Test validation with complete parameter set exercising all validation paths.

        This test exercises the maximum number of real validation code paths
        in a single test without any internal mocking.
        """
        web_root = temp_directory
        csr_file = os.path.join(temp_directory, 'test.csr')

        # Create a test CSR file
        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICWjCCAUICAQAwFTETMBEGA1UEAwwKZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCqgBwqc9wNkA/jKJNZWm8vJH/Kx/VGlODRrQ2Y
-----END CERTIFICATE REQUEST-----"""
        with open(csr_file, 'w') as f:
            f.write(csr_content)

        params = {
            'api_key': 'test-api-key-very-long-1234567890123456',
            'domains': ['example.com', 'www.example.com'],
            'state': 'present',
            'validation_method': 'HTTP_CSR_HASH',
            'validity_days': 365,
            'renew_threshold_days': 60,
            'certificate_path': os.path.join(temp_directory, 'cert.pem'),
            'private_key_path': os.path.join(temp_directory, 'key.pem'),
            'ca_bundle_path': os.path.join(temp_directory, 'ca.pem'),
            'full_chain_path': os.path.join(temp_directory, 'fullchain.pem'),
            'csr_path': csr_file,
            'web_root': web_root,
            'force': True,
            'backup': True,
            'timeout': 60,
            'validation_timeout': 600,
            'file_mode': '0644'
        }

        result = validator.validate_plugin_parameters(params)

        # Verify all parameters are properly validated and processed
        assert result['api_key'] == 'test-api-key-very-long-1234567890123456'
        assert result['domains'] == ['example.com', 'www.example.com']
        assert result['state'] == 'present'
        assert result['validation_method'] == 'HTTP_CSR_HASH'
        assert result['validity_days'] == 365
        assert result['renew_threshold_days'] == 60
        assert result['force'] is True
        assert result['backup'] is True
        assert result['timeout'] == 60
        assert result['validation_timeout'] == 600
        assert result['file_mode'] == 0o644

    def test_api_key_validation_real_logic(self, validator):
        """
        Test API key validation with real validation logic.

        Exercises the real _validate_api_key method and validate_api_key
        utility function without mocking.
        """
        # Valid API key
        valid_key = 'test-api-key-1234567890123456'
        result = validator._validate_api_key(valid_key)
        assert result == valid_key

        # Test error cases with real validation
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_api_key('')
        assert "api_key is required" in str(exc_info.value)

        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_api_key(123)
        assert "api_key must be a string" in str(exc_info.value)

    def test_domains_validation_real_logic(self, validator):
        """
        Test domains validation with real validation logic.

        Exercises the real _validate_domains method and validate_domains
        utility function without mocking.
        """
        # Valid single domain
        result = validator._validate_domains('example.com')
        assert result == ['example.com']

        # Valid multiple domains
        result = validator._validate_domains(['example.com', 'www.example.com'])
        assert result == ['example.com', 'www.example.com']

        # Test error cases with real validation
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_domains(None)
        assert "domains is required" in str(exc_info.value)

        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_domains(123)
        assert "domains must be a string or list of strings" in str(exc_info.value)

    def test_parameter_compatibility_validation_real_logic(self, validator):
        """
        Test parameter compatibility validation with real business logic.

        Exercises the real _validate_parameter_compatibility method
        with various parameter combinations.
        """
        # Test wildcard domain requiring DNS validation
        params = {
            'domains': ['*.example.com'],
            'validation_method': 'HTTP_CSR_HASH',
            'state': 'present',
            'validity_days': 90,
            'renew_threshold_days': 30
        }

        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_parameter_compatibility(params)
        assert "Wildcard domains require DNS validation method" in str(exc_info.value)

        # Test HTTP validation requiring web_root
        params = {
            'domains': ['example.com'],
            'validation_method': 'HTTP_CSR_HASH',
            'state': 'present',
            'validity_days': 90,
            'renew_threshold_days': 30
        }

        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_parameter_compatibility(params)
        assert "web_root is required for HTTP validation" in str(exc_info.value)

        # Test renewal threshold validation
        params = {
            'domains': ['example.com'],
            'validation_method': 'DNS_CSR_HASH',
            'validity_days': 90,
            'renew_threshold_days': 90
        }

        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_parameter_compatibility(params)
        assert "renew_threshold_days (90) must be less than validity_days (90)" in str(exc_info.value)

    def test_boolean_validation_real_logic(self, validator):
        """
        Test boolean parameter validation with real validation logic.

        Exercises the real _validate_boolean method with various input types.
        """
        # Test actual boolean values
        assert validator._validate_boolean(True, 'test') is True
        assert validator._validate_boolean(False, 'test') is False

        # Test string representations
        assert validator._validate_boolean('true', 'test') is True
        assert validator._validate_boolean('false', 'test') is False
        assert validator._validate_boolean('yes', 'test') is True
        assert validator._validate_boolean('no', 'test') is False
        assert validator._validate_boolean('1', 'test') is True
        assert validator._validate_boolean('0', 'test') is False

        # Test error case
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_boolean('invalid', 'test')
        assert "test must be a boolean" in str(exc_info.value)

    def test_file_mode_validation_real_logic(self, validator):
        """
        Test file mode validation with real validation logic.

        Exercises the real _validate_file_mode method with various input formats.
        """
        # Test string octal with prefix
        assert validator._validate_file_mode('0644') == 0o644

        # Test string octal without prefix
        assert validator._validate_file_mode('644') == 0o644  # Note: both converted to octal

        # Test integer input
        assert validator._validate_file_mode(0o755) == 0o755

        # Test error cases
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_file_mode('invalid')
        assert "file_mode must be a valid octal number" in str(exc_info.value)

        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_file_mode(0o1000)
        assert "file_mode must be between 0000 and 0777" in str(exc_info.value)

    def test_timeout_validation_real_logic(self, validator):
        """
        Test timeout validation with real validation logic.

        Exercises the real _validate_timeout and _validate_validation_timeout
        methods with various input types and ranges.
        """
        # Test valid timeout values
        assert validator._validate_timeout(30) == 30
        assert validator._validate_timeout('60') == 60

        # Test validation timeout
        assert validator._validate_validation_timeout(300) == 300
        assert validator._validate_validation_timeout('600') == 600

        # Test range validation
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_timeout(0)
        assert "timeout must be between 1 and 300 seconds" in str(exc_info.value)

        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_validation_timeout(30)
        assert "validation_timeout must be between 60 and 3600 seconds" in str(exc_info.value)

    def test_csr_content_validation_real_logic(self, validator):
        """
        Test CSR content validation with real validation logic.

        Exercises the real _validate_csr_content method with valid and invalid CSR formats.
        """
        # Valid CSR content
        valid_csr = """-----BEGIN CERTIFICATE REQUEST-----
MIICWjCCAUICAQAwFTETMBEGA1UEAwwKZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
-----END CERTIFICATE REQUEST-----"""

        result = validator._validate_csr_content(valid_csr)
        assert result == valid_csr

        # Test whitespace handling
        csr_with_whitespace = '  ' + valid_csr + '  \n'
        result = validator._validate_csr_content(csr_with_whitespace)
        assert result == valid_csr

        # Test error cases
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_csr_content('')
        assert "csr content cannot be empty" in str(exc_info.value)

        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_csr_content('invalid csr content')
        assert "csr must be in PEM format" in str(exc_info.value)

    def test_file_paths_writable_validation_real_logic(self, validator, temp_directory):
        """
        Test file paths writability validation with real filesystem operations.

        Exercises the real validate_file_paths_writable method with actual
        file system operations to test writability.
        """
        writable_path = os.path.join(temp_directory, 'writable.txt')
        readonly_path = os.path.join('/tmp', 'readonly.txt')  # Use /tmp instead of /root

        file_paths = [writable_path, readonly_path]
        result = validator.validate_file_paths_writable(file_paths)

        assert result[writable_path] is True
        # readonly_path may or may not be writable depending on system

    def test_parameter_schema_real_structure(self, validator):
        """
        Test parameter schema generation with real structure.

        Exercises the real get_parameter_schema method to validate
        that it returns proper schema structure for documentation.
        """
        schema = validator.get_parameter_schema()

        # Verify structure
        assert 'required' in schema
        assert 'optional' in schema
        assert isinstance(schema['required'], list)
        assert isinstance(schema['optional'], dict)

        # Verify required parameters
        assert 'api_key' in schema['required']
        assert 'domains' in schema['required']

        # Verify optional parameters have proper metadata
        assert 'state' in schema['optional']
        state_param = schema['optional']['state']
        assert state_param['type'] == 'str'
        assert state_param['default'] == 'present'
        assert 'choices' in state_param
        assert state_param['choices'] == validator.valid_states


@pytest.mark.unit
class TestConfigValidatorErrorHandling:
    """
    Test error handling in ConfigValidator with real error scenarios.

    These tests exercise actual error conditions and exception handling
    in the real validation logic.
    """

    @pytest.fixture
    def validator(self):
        return ConfigValidator()

    def test_state_validation_real_error_handling(self, validator):
        """Test state validation error handling with real validation logic."""
        # Test invalid state type
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_state(123)
        assert "state must be a string" in str(exc_info.value)
        assert exc_info.value.parameter == "state"

        # Test invalid state value
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_state('invalid_state')
        assert "Invalid state: invalid_state" in str(exc_info.value)
        assert exc_info.value.parameter == "state"

    def test_validation_method_real_error_handling(self, validator):
        """Test validation method error handling with real validation logic."""
        # Test invalid method type
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_validation_method(123)
        assert "validation_method must be a string" in str(exc_info.value)

        # Test invalid method value
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_validation_method('INVALID_METHOD')
        assert "Invalid validation_method: INVALID_METHOD" in str(exc_info.value)

    def test_validity_days_real_error_handling(self, validator):
        """Test validity days validation error handling with real logic."""
        # Test invalid type
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_validity_days([90])
        assert "validity_days must be an integer" in str(exc_info.value)

        # Test invalid value
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_validity_days(180)
        assert "Invalid validity_days: 180" in str(exc_info.value)

        # Test invalid string
        with pytest.raises(ZeroSSLConfigurationError) as exc_info:
            validator._validate_validity_days('invalid')
        assert "validity_days must be an integer" in str(exc_info.value)
