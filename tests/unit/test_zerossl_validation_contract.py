# -*- coding: utf-8 -*-
"""
Improved Contract Tests for ZeroSSL Validation API Integration.

Follows improved test design patterns:
- Mock only at HTTP/DNS/filesystem boundaries
- Use real ValidationHandler method calls
- Test realistic ZeroSSL validation scenarios
- Exercise actual validation workflow logic
"""

import pytest
import time
import requests
import dns.resolver
from pathlib import Path
from unittest.mock import Mock
from plugins.module_utils.zerossl.validation_handler import ValidationHandler
from plugins.module_utils.zerossl.exceptions import ZeroSSLValidationError, ZeroSSLFileSystemError


@pytest.mark.unit
class TestHTTPValidationContractImproved:
    """Improved contract tests for HTTP-01 domain validation with boundary mocking only."""

    def test_http_validation_file_structure_processing(self):
        """Test that HTTP validation files are structured correctly by real validation logic."""
        # Arrange: Real ValidationHandler and realistic ZeroSSL validation data
        handler = ValidationHandler()
        realistic_zerossl_data = {
            "ecommerce.example.com": {
                "file_validation_url_http": "http://ecommerce.example.com/.well-known/pki-validation/G7H8I9J0K1L2M3N4.txt",
                "file_validation_content": ["G7H8I9J0K1L2M3N4", "comodoca.com", "O5P6Q7R8S9T0U1V2"]
            },
            "api.ecommerce.example.com": {
                "file_validation_url_http": "http://api.ecommerce.example.com/.well-known/pki-validation/H8I9J0K1L2M3N4O5.txt",
                "file_validation_content": ["H8I9J0K1L2M3N4O5", "sectigo.com", "P6Q7R8S9T0U1V2W3"]
            }
        }

        # Act: Call real validation handler method - exercises actual file preparation logic
        validation_files = handler.prepare_http_validation(realistic_zerossl_data)

        # Assert: Verify real method produced correct structure
        assert len(validation_files) == 2

        for validation_file in validation_files:
            # Verify required fields present
            required_fields = ['domain', 'filename', 'content', 'url_path', 'full_url']
            for field in required_fields:
                assert field in validation_file, f"Missing required field: {field}"

            # Verify realistic ZeroSSL file structure
            assert validation_file['domain'] in ["ecommerce.example.com", "api.ecommerce.example.com"]
            assert validation_file['url_path'].startswith('/.well-known/pki-validation/')
            assert validation_file['filename'].endswith('.txt')
            assert len(validation_file['filename']) == 20  # ZeroSSL token filename length
            assert isinstance(validation_file['content'], list)
            assert len(validation_file['content']) == 3  # ZeroSSL content format

        # Verify domain-specific file details
        ecommerce_file = next(vf for vf in validation_files if vf['domain'] == 'ecommerce.example.com')
        assert ecommerce_file['filename'] == 'G7H8I9J0K1L2M3N4.txt'
        assert ecommerce_file['content'] == ["G7H8I9J0K1L2M3N4", "comodoca.com", "O5P6Q7R8S9T0U1V2"]
        assert ecommerce_file['full_url'] == "http://ecommerce.example.com/.well-known/pki-validation/G7H8I9J0K1L2M3N4.txt"

    def test_http_validation_file_placement_filesystem_operations(self, temp_directory):
        """Test HTTP validation file placement with real filesystem operations."""
        # Arrange: Real ValidationHandler and realistic validation files
        handler = ValidationHandler()
        realistic_validation_files = [
            {
                'domain': 'shop.example.com',
                'filename': 'I9J0K1L2M3N4O5P6.txt',
                'content': ['I9J0K1L2M3N4O5P6', 'comodoca.com', 'Q7R8S9T0U1V2W3X4'],
                'url_path': '/.well-known/pki-validation/I9J0K1L2M3N4O5P6.txt'
            },
            {
                'domain': 'checkout.example.com',
                'filename': 'J0K1L2M3N4O5P6Q7.txt',
                'content': ['J0K1L2M3N4O5P6Q7', 'sectigo.com', 'R8S9T0U1V2W3X4Y5'],
                'url_path': '/.well-known/pki-validation/J0K1L2M3N4O5P6Q7.txt'
            }
        ]

        # Act: Call real file placement method - exercises actual filesystem operations
        result = handler.place_validation_files(realistic_validation_files, str(temp_directory))

        # Assert: Verify real filesystem operations completed successfully
        assert result['success'] is True
        assert result['error'] is None
        assert len(result['files_created']) == 2

        # Verify actual files created on filesystem
        for file_info in result['files_created']:
            file_path = Path(file_info['path'])
            assert file_path.exists()
            assert file_path.is_file()

            # Verify file content matches ZeroSSL format
            actual_content = file_path.read_text()
            original_file = next(vf for vf in realistic_validation_files if vf['filename'] == file_path.name)
            expected_content = '\n'.join(original_file['content'])
            assert actual_content == expected_content

        # Verify proper directory structure created
        well_known_path = temp_directory / '.well-known' / 'pki-validation'
        assert well_known_path.exists()
        assert well_known_path.is_dir()

        # Verify individual files exist with correct names
        shop_file = well_known_path / 'I9J0K1L2M3N4O5P6.txt'
        checkout_file = well_known_path / 'J0K1L2M3N4O5P6Q7.txt'
        assert shop_file.exists()
        assert checkout_file.exists()

    def test_http_validation_url_verification_with_realistic_scenarios(self, mocker):
        """Test HTTP validation URL verification with realistic response scenarios."""
        # Arrange: Real ValidationHandler for HTTP verification testing
        handler = ValidationHandler(http_timeout=10)
        test_scenarios = [
            # (url, expected_content, mock_status, mock_response_text, expected_accessible, expected_match)
            (
                "http://store.example.com/.well-known/pki-validation/K1L2M3N4O5P6Q7R8.txt",
                "K1L2M3N4O5P6Q7R8\ncomodoca.com\nS9T0U1V2W3X4Y5Z6",
                200,
                "K1L2M3N4O5P6Q7R8\ncomodoca.com\nS9T0U1V2W3X4Y5Z6",
                True,
                True
            ),
            (
                "https://secure.example.com/.well-known/pki-validation/L2M3N4O5P6Q7R8S9.txt",
                "L2M3N4O5P6Q7R8S9\nsectigo.com\nT0U1V2W3X4Y5Z6A7",
                200,
                "L2M3N4O5P6Q7R8S9\nsectigo.com\nT0U1V2W3X4Y5Z6A7",
                True,
                True
            )
        ]

        for url, expected_content, mock_status, mock_text, expected_accessible, expected_match in test_scenarios:
            # Mock only HTTP boundary - simulate web server response
            mock_response = Mock()
            mock_response.status_code = mock_status
            mock_response.text = mock_text
            mocker.patch('requests.get', return_value=mock_response)

            # Act: Call real HTTP verification method - exercises actual verification logic
            result = handler.verify_http_validation(url, expected_content)

            # Assert: Verify real verification processing
            assert result['accessible'] == expected_accessible
            assert result['content_match'] == expected_match
            assert result['status_code'] == mock_status
            assert result['error'] is None

            # Verify HTTP call was made with correct parameters
            requests.get.assert_called_with(url, timeout=10)

    def test_http_validation_failure_scenario_handling(self, mocker):
        """Test HTTP validation failure handling with realistic error scenarios."""
        # Arrange: Real ValidationHandler for failure testing
        handler = ValidationHandler()
        validation_url = "http://failing.example.com/.well-known/pki-validation/M3N4O5P6Q7R8S9T0.txt"
        expected_content = "M3N4O5P6Q7R8S9T0\ncomodoca.com\nU1V2W3X4Y5Z6A7B8"

        # Test realistic HTTP error scenarios
        error_scenarios = [
            (404, "Not Found", False, False, "not accessible"),
            (403, "Forbidden", False, False, "not accessible"),  # 403 also results in "not accessible"
            (500, "Internal Server Error", False, False, "not accessible"),  # 500 also results in "not accessible"
            (200, "WRONG_VALIDATION_CONTENT", True, False, None),  # Content mismatch
            (200, "M3N4O5P6Q7R8S9T0\ncomodoca.com\nWRONG_TOKEN", True, False, None)  # Partial mismatch
        ]

        for status_code, response_text, expected_accessible, expected_match, expected_error_keyword in error_scenarios:
            # Mock only HTTP boundary - simulate various server responses
            mock_response = Mock()
            mock_response.status_code = status_code
            mock_response.text = response_text
            mocker.patch('requests.get', return_value=mock_response)

            # Act: Call real HTTP verification method - exercises actual error handling
            result = handler.verify_http_validation(validation_url, expected_content)

            # Assert: Verify real error detection and categorization
            assert result['accessible'] == expected_accessible
            assert result['content_match'] == expected_match
            assert result['status_code'] == status_code

            if expected_error_keyword:
                assert expected_error_keyword in result['error'].lower()

    def test_http_validation_network_error_handling(self, mocker):
        """Test HTTP validation with realistic network error conditions."""
        # Arrange: Real ValidationHandler for network error testing
        handler = ValidationHandler(http_timeout=5)
        validation_url = "http://unreachable.example.com/.well-known/pki-validation/N4O5P6Q7R8S9T0U1.txt"
        expected_content = "N4O5P6Q7R8S9T0U1\nsectigo.com\nV2W3X4Y5Z6A7B8C9"

        # Test different network error scenarios
        network_errors = [
            (requests.exceptions.Timeout("Connection timeout"), "timeout"),
            (requests.exceptions.ConnectionError("Connection refused"), "connection"),
            (requests.exceptions.RequestException("Network error"), "network error")
        ]

        for exception, expected_error_type in network_errors:
            # Mock only HTTP boundary - simulate network-level errors
            mocker.patch('requests.get', side_effect=exception)

            # Act: Call real HTTP verification method - exercises actual network error handling
            result = handler.verify_http_validation(validation_url, expected_content)

            # Assert: Verify real network error handling
            assert result['accessible'] is False
            assert result['content_match'] is False
            assert result['status_code'] is None
            assert expected_error_type in result['error'].lower()

    def test_http_validation_performance_requirements(self, mocker):
        """Test HTTP validation performance meets contract requirements."""
        # Arrange: Real ValidationHandler for performance testing
        handler = ValidationHandler(http_timeout=3)
        validation_url = "http://performance.example.com/.well-known/pki-validation/O5P6Q7R8S9T0U1V2.txt"
        expected_content = "O5P6Q7R8S9T0U1V2\ncomodoca.com\nW3X4Y5Z6A7B8C9D0"

        # Mock only HTTP boundary - simulate fast response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = expected_content
        mocker.patch('requests.get', return_value=mock_response)

        # Act: Measure real method execution time
        start_time = time.time()
        result = handler.verify_http_validation(validation_url, expected_content)
        execution_time = time.time() - start_time

        # Assert: Verify performance requirements met
        assert execution_time < 5.0  # Contract requirement: individual test <5s
        assert result['accessible'] is True
        assert result['content_match'] is True


@pytest.mark.unit
class TestDNSValidationContractImproved:
    """Improved contract tests for DNS-01 domain validation with boundary mocking only."""

    def test_dns_validation_record_structure_processing(self):
        """Test DNS validation record preparation with real ValidationHandler processing."""
        # Arrange: Real ValidationHandler and realistic ZeroSSL DNS validation data
        handler = ValidationHandler()
        realistic_dns_data = {
            "corporate.example.com": {
                "cname_validation_p1": "P6Q7R8S9T0U1V2W3.corporate.example.com",
                "cname_validation_p2": "P6Q7R8S9T0U1V2W3.X4Y5Z6A7B8C9D0E1.F2G3H4I5J6K7L8M9.zerossl.com"
            },
            "*.corporate.example.com": {
                "cname_validation_p1": "Q7R8S9T0U1V2W3X4.corporate.example.com",
                "cname_validation_p2": "Q7R8S9T0U1V2W3X4.Y5Z6A7B8C9D0E1F2.G3H4I5J6K7L8M9N0.zerossl.com"
            }
        }

        # Act: Call real DNS preparation method - exercises actual record creation logic
        dns_records = handler.prepare_dns_validation(realistic_dns_data)

        # Assert: Verify real method produced correct DNS record structure
        assert len(dns_records) == 2

        for record in dns_records:
            # Verify required DNS record fields
            required_fields = ['domain', 'record_name', 'record_type', 'record_value']
            for field in required_fields:
                assert field in record, f"Missing required DNS field: {field}"

            # Verify ZeroSSL DNS record format
            assert record['record_type'] == 'CNAME'
            assert record['record_name'].endswith('.corporate.example.com')
            assert record['record_value'].endswith('.zerossl.com')
            assert len(record['record_name'].split('.')[0]) == 16  # ZeroSSL token length

        # Verify specific domain records
        corporate_record = next(r for r in dns_records if r['domain'] == 'corporate.example.com')
        wildcard_record = next(r for r in dns_records if r['domain'] == '*.corporate.example.com')

        assert corporate_record['record_name'] == 'P6Q7R8S9T0U1V2W3.corporate.example.com'
        assert corporate_record['record_value'] == 'P6Q7R8S9T0U1V2W3.X4Y5Z6A7B8C9D0E1.F2G3H4I5J6K7L8M9.zerossl.com'

        assert wildcard_record['record_name'] == 'Q7R8S9T0U1V2W3X4.corporate.example.com'
        assert wildcard_record['record_value'] == 'Q7R8S9T0U1V2W3X4.Y5Z6A7B8C9D0E1F2.G3H4I5J6K7L8M9N0.zerossl.com'

    def test_dns_record_verification_with_realistic_resolution(self, mocker):
        """Test DNS record verification with realistic DNS resolution scenarios."""
        # Arrange: Real ValidationHandler for DNS verification testing
        handler = ValidationHandler(dns_timeout=30)
        test_scenarios = [
            # (record_name, expected_value, mock_resolved_value, expected_exists, expected_match)
            (
                "R8S9T0U1V2W3X4Y5.enterprise.example.com",
                "R8S9T0U1V2W3X4Y5.Z6A7B8C9D0E1F2G3.H4I5J6K7L8M9N0O1.zerossl.com",
                "R8S9T0U1V2W3X4Y5.Z6A7B8C9D0E1F2G3.H4I5J6K7L8M9N0O1.zerossl.com.",  # DNS trailing dot
                True,
                True
            ),
            (
                "S9T0U1V2W3X4Y5Z6.marketing.example.com",
                "S9T0U1V2W3X4Y5Z6.A7B8C9D0E1F2G3H4.I5J6K7L8M9N0O1P2.zerossl.com",
                "S9T0U1V2W3X4Y5Z6.A7B8C9D0E1F2G3H4.I5J6K7L8M9N0O1P2.zerossl.com.",
                True,
                True
            )
        ]

        for record_name, expected_value, mock_resolved_value, expected_exists, expected_match in test_scenarios:
            # Mock only DNS boundary - simulate DNS resolver response
            mock_record = Mock()
            mock_record.to_text.return_value = mock_resolved_value
            mock_resolver = Mock()
            mock_resolver.resolve.return_value = [mock_record]
            mock_resolver.timeout = 30
            mock_resolver.lifetime = 30
            mocker.patch('dns.resolver.Resolver', return_value=mock_resolver)

            # Act: Call real DNS verification method - exercises actual DNS validation logic
            result = handler.verify_dns_validation(record_name, expected_value)

            # Assert: Verify real DNS verification processing
            assert result['record_exists'] == expected_exists
            assert result['value_match'] == expected_match
            assert result['actual_values'] == [expected_value]  # Cleaned value (no trailing dot)
            assert result['error'] is None

            # Verify DNS query parameters
            mock_resolver.resolve.assert_called_with(record_name, 'CNAME')

    def test_dns_validation_failure_scenario_handling(self, mocker):
        """Test DNS validation failure handling with realistic DNS error conditions."""
        # Arrange: Real ValidationHandler for DNS failure testing
        handler = ValidationHandler()
        record_name = "T0U1V2W3X4Y5Z6A7.services.example.com"
        expected_value = "T0U1V2W3X4Y5Z6A7.B8C9D0E1F2G3H4I5.J6K7L8M9N0O1P2Q3.zerossl.com"

        # Test realistic DNS error scenarios
        dns_error_scenarios = [
            (dns.resolver.NXDOMAIN(), "DNS record not found", False, False),
            (dns.resolver.NoAnswer(), "No CNAME record found", False, False),
            (dns.resolver.Timeout(), "resolution lifetime expired", False, False)  # Actual DNS timeout message
        ]

        for dns_exception, expected_error_type, expected_exists, expected_match in dns_error_scenarios:
            # Mock only DNS boundary - simulate DNS resolver errors
            mock_resolver = Mock()
            mock_resolver.resolve.side_effect = dns_exception
            mocker.patch('dns.resolver.Resolver', return_value=mock_resolver)

            # Act: Call real DNS verification method - exercises actual DNS error handling
            result = handler.verify_dns_validation(record_name, expected_value)

            # Assert: Verify real DNS error handling
            assert result['record_exists'] == expected_exists
            assert result['value_match'] == expected_match
            assert result['actual_values'] == []
            assert expected_error_type.lower() in result['error'].lower()

    def test_dns_validation_value_mismatch_detection(self, mocker):
        """Test DNS validation value mismatch detection with real comparison logic."""
        # Arrange: Real ValidationHandler for value mismatch testing
        handler = ValidationHandler()
        record_name = "U1V2W3X4Y5Z6A7B8.finance.example.com"
        expected_value = "U1V2W3X4Y5Z6A7B8.C9D0E1F2G3H4I5J6.K7L8M9N0O1P2Q3R4.zerossl.com"

        # Mock only DNS boundary - simulate wrong CNAME value
        wrong_values = [
            "WRONG_TOKEN.C9D0E1F2G3H4I5J6.K7L8M9N0O1P2Q3R4.zerossl.com.",
            "U1V2W3X4Y5Z6A7B8.WRONG_MIDDLE.K7L8M9N0O1P2Q3R4.zerossl.com.",
            "U1V2W3X4Y5Z6A7B8.C9D0E1F2G3H4I5J6.WRONG_SUFFIX.zerossl.com."
        ]

        for wrong_value in wrong_values:
            mock_record = Mock()
            mock_record.to_text.return_value = wrong_value
            mock_resolver = Mock()
            mock_resolver.resolve.return_value = [mock_record]
            mocker.patch('dns.resolver.Resolver', return_value=mock_resolver)

            # Act: Call real DNS verification method - exercises actual value comparison logic
            result = handler.verify_dns_validation(record_name, expected_value)

            # Assert: Verify real mismatch detection
            assert result['record_exists'] is True  # Record found
            assert result['value_match'] is False   # But value doesn't match
            assert result['actual_values'] == [wrong_value.rstrip('.')]  # Cleaned actual value
            # Error field may be None when record exists but value doesn't match
            if result.get('error'):
                assert 'mismatch' in result['error'].lower() or 'does not match' in result['error'].lower()

    def test_wildcard_domain_dns_validation_handling(self):
        """Test DNS validation for wildcard domains with real processing logic."""
        # Arrange: Real ValidationHandler and wildcard domain validation
        handler = ValidationHandler()
        wildcard_dns_data = {
            "*.services.example.com": {
                "cname_validation_p1": "V2W3X4Y5Z6A7B8C9.services.example.com",
                "cname_validation_p2": "V2W3X4Y5Z6A7B8C9.D0E1F2G3H4I5J6K7.L8M9N0O1P2Q3R4S5.zerossl.com"
            },
            "*.api.services.example.com": {
                "cname_validation_p1": "W3X4Y5Z6A7B8C9D0.api.services.example.com",
                "cname_validation_p2": "W3X4Y5Z6A7B8C9D0.E1F2G3H4I5J6K7L8.M9N0O1P2Q3R4S5T6.zerossl.com"
            }
        }

        # Act: Call real DNS preparation method - exercises actual wildcard handling logic
        dns_records = handler.prepare_dns_validation(wildcard_dns_data)

        # Assert: Verify real wildcard domain processing
        assert len(dns_records) == 2

        # Verify first wildcard record
        services_wildcard = next(r for r in dns_records if r['domain'] == '*.services.example.com')
        assert services_wildcard['record_name'] == 'V2W3X4Y5Z6A7B8C9.services.example.com'
        assert services_wildcard['record_value'] == 'V2W3X4Y5Z6A7B8C9.D0E1F2G3H4I5J6K7.L8M9N0O1P2Q3R4S5.zerossl.com'
        assert services_wildcard['record_type'] == 'CNAME'

        # Verify second wildcard subdomain record
        api_services_wildcard = next(r for r in dns_records if r['domain'] == '*.api.services.example.com')
        assert api_services_wildcard['record_name'] == 'W3X4Y5Z6A7B8C9D0.api.services.example.com'
        assert 'api.services.example.com' in api_services_wildcard['record_name']

    def test_dns_instructions_generation_with_realistic_records(self):
        """Test DNS instruction generation with realistic record sets."""
        # Arrange: Real ValidationHandler and realistic DNS records
        handler = ValidationHandler()
        realistic_dns_records = [
            {
                'domain': 'platform.example.com',
                'record_name': 'X4Y5Z6A7B8C9D0E1.platform.example.com',
                'record_type': 'CNAME',
                'record_value': 'X4Y5Z6A7B8C9D0E1.F2G3H4I5J6K7L8M9.N0O1P2Q3R4S5T6U7.zerossl.com'
            },
            {
                'domain': '*.platform.example.com',
                'record_name': 'Y5Z6A7B8C9D0E1F2.platform.example.com',
                'record_type': 'CNAME',
                'record_value': 'Y5Z6A7B8C9D0E1F2.G3H4I5J6K7L8M9N0.O1P2Q3R4S5T6U7V8.zerossl.com'
            }
        ]

        # Act: Call real instruction generation method - exercises actual instruction formatting
        instructions = handler.generate_dns_instructions(realistic_dns_records)

        # Assert: Verify real instruction generation
        assert 'records_to_create' in instructions
        assert 'instructions' in instructions
        assert instructions['records_to_create'] == realistic_dns_records

        # Verify instruction content format
        instruction_text = instructions['instructions']
        assert isinstance(instruction_text, str)
        assert len(instruction_text) > 0
        assert 'DNS Records to Create' in instruction_text
        assert 'CNAME' in instruction_text
        assert 'platform.example.com' in instruction_text
        assert 'zerossl.com' in instruction_text
        assert 'DNS propagation' in instruction_text or 'propagation may take' in instruction_text


@pytest.mark.unit
class TestValidationWorkflowContractImproved:
    """Improved contract tests for complete validation workflows with realistic scenarios."""

    def test_complete_http_validation_workflow_integration(self, temp_directory, mocker):
        """Test complete HTTP validation workflow with real method integration."""
        # Arrange: Real ValidationHandler for complete workflow testing
        handler = ValidationHandler()
        domains = ["workflow.example.com", "api.workflow.example.com"]

        # Mock realistic ZeroSSL validation data
        zerossl_validation_data = {
            "workflow.example.com": {
                "file_validation_url_http": "http://workflow.example.com/.well-known/pki-validation/Z6A7B8C9D0E1F2G3.txt",
                "file_validation_content": ["Z6A7B8C9D0E1F2G3", "comodoca.com", "H4I5J6K7L8M9N0O1"]
            },
            "api.workflow.example.com": {
                "file_validation_url_http": "http://api.workflow.example.com/.well-known/pki-validation/A7B8C9D0E1F2G3H4.txt",
                "file_validation_content": ["A7B8C9D0E1F2G3H4", "sectigo.com", "I5J6K7L8M9N0O1P2"]
            }
        }

        # Step 1: Prepare validation files - real method call
        validation_files = handler.prepare_http_validation(zerossl_validation_data)
        assert len(validation_files) == 2

        # Step 2: Place validation files - real filesystem operations
        placement_result = handler.place_validation_files(validation_files, str(temp_directory))
        assert placement_result['success'] is True
        assert len(placement_result['files_created']) == 2

        # Step 3: Verify files are accessible - mock only HTTP boundary
        for vf in validation_files:
            # Mock only HTTP boundary - simulate web server serving validation file
            expected_content = '\n'.join(vf['content'])
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = expected_content
            mocker.patch('requests.get', return_value=mock_response)

            # Act: Call real HTTP verification method
            verification_result = handler.verify_http_validation(vf['full_url'], expected_content)

            # Assert: Verify real verification logic
            assert verification_result['accessible'] is True
            assert verification_result['content_match'] is True
            assert verification_result['status_code'] == 200

        # Step 4: Clean up validation files - real filesystem cleanup
        cleanup_result = handler.cleanup_validation_files(placement_result['files_created'])
        assert cleanup_result['success'] is True
        assert len(cleanup_result['files_removed']) == 2

    def test_complete_dns_validation_workflow_integration(self, mocker):
        """Test complete DNS validation workflow with real method integration."""
        # Arrange: Real ValidationHandler for DNS workflow testing
        handler = ValidationHandler()

        # Mock realistic ZeroSSL DNS validation data
        dns_validation_data = {
            "platform.example.com": {
                "cname_validation_p1": "B8C9D0E1F2G3H4I5.platform.example.com",
                "cname_validation_p2": "B8C9D0E1F2G3H4I5.J6K7L8M9N0O1P2Q3.R4S5T6U7V8W9X0Y1.zerossl.com"
            },
            "*.platform.example.com": {
                "cname_validation_p1": "C9D0E1F2G3H4I5J6.platform.example.com",
                "cname_validation_p2": "C9D0E1F2G3H4I5J6.K7L8M9N0O1P2Q3R4.S5T6U7V8W9X0Y1Z2.zerossl.com"
            }
        }

        # Step 1: Prepare DNS records - real method call
        dns_records = handler.prepare_dns_validation(dns_validation_data)
        assert len(dns_records) == 2

        # Step 2: Generate DNS instructions - real method call
        instructions = handler.generate_dns_instructions(dns_records)
        assert 'records_to_create' in instructions
        assert len(instructions['records_to_create']) == 2

        # Step 3: Verify DNS records - mock only DNS boundary
        for record in dns_records:
            # Mock only DNS boundary - simulate DNS resolver with correct CNAME
            mock_dns_record = Mock()
            mock_dns_record.to_text.return_value = f"{record['record_value']}."
            mock_resolver = Mock()
            mock_resolver.resolve.return_value = [mock_dns_record]
            mocker.patch('dns.resolver.Resolver', return_value=mock_resolver)

            # Act: Call real DNS verification method
            verification_result = handler.verify_dns_validation(record['record_name'], record['record_value'])

            # Assert: Verify real DNS verification logic
            assert verification_result['record_exists'] is True
            assert verification_result['value_match'] is True
            assert verification_result['actual_values'] == [record['record_value']]

    def test_mixed_validation_method_workflow(self, temp_directory, mocker):
        """Test workflow mixing HTTP and DNS validation methods."""
        # Arrange: Real ValidationHandler for mixed validation testing
        handler = ValidationHandler()

        # HTTP validation for regular domains
        http_domains = ["mixed1.example.com", "mixed2.example.com"]
        http_validation_data = {
            domain: {
                "file_validation_url_http": f"http://{domain}/.well-known/pki-validation/MIXED{i}.txt",
                "file_validation_content": [f"MIXED{i}TOKEN", "comodoca.com", f"MIXED{i}VALIDATION"]
            }
            for i, domain in enumerate(http_domains, 1)
        }

        # DNS validation for wildcard domains
        dns_validation_data = {
            "*.mixed.example.com": {
                "cname_validation_p1": "MIXEDDNS001.mixed.example.com",
                "cname_validation_p2": "MIXEDDNS001.MIXEDDNS002.MIXEDDNS003.zerossl.com"
            }
        }

        # Step 1: Process HTTP validation - real methods
        http_files = handler.prepare_http_validation(http_validation_data)
        http_placement = handler.place_validation_files(http_files, str(temp_directory))
        assert http_placement['success'] is True

        # Step 2: Process DNS validation - real methods
        dns_records = handler.prepare_dns_validation(dns_validation_data)
        dns_instructions = handler.generate_dns_instructions(dns_records)
        assert len(dns_records) == 1

        # Step 3: Validate suggested method selection - real logic
        all_domains = http_domains + list(dns_validation_data.keys())
        suggested_method = handler.suggest_validation_method(all_domains)
        assert suggested_method == 'DNS_CSR_HASH'  # Wildcard domains require DNS

        # Step 4: Verify both validation types work
        # HTTP verification with mocked HTTP boundary
        for http_file in http_files:
            expected_content = '\n'.join(http_file['content'])
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = expected_content
            mocker.patch('requests.get', return_value=mock_response)

            result = handler.verify_http_validation(http_file['full_url'], expected_content)
            assert result['accessible'] is True
            assert result['content_match'] is True

        # DNS verification with mocked DNS boundary
        for dns_record in dns_records:
            mock_dns_record = Mock()
            mock_dns_record.to_text.return_value = f"{dns_record['record_value']}."
            mock_resolver = Mock()
            mock_resolver.resolve.return_value = [mock_dns_record]
            mocker.patch('dns.resolver.Resolver', return_value=mock_resolver)

            result = handler.verify_dns_validation(dns_record['record_name'], dns_record['record_value'])
            assert result['record_exists'] is True
            assert result['value_match'] is True

    def test_validation_workflow_performance_compliance(self, temp_directory, mocker):
        """Test validation workflow performance meets contract requirements."""
        # Arrange: Real ValidationHandler for performance testing
        handler = ValidationHandler()
        domains = [f"perf{i}.example.com" for i in range(5)]  # 5 domains for performance test

        # Create validation data for multiple domains
        validation_data = {
            domain: {
                "file_validation_url_http": f"http://{domain}/.well-known/pki-validation/PERF{i}.txt",
                "file_validation_content": [f"PERF{i}TOKEN", "comodoca.com", f"PERF{i}VALIDATION"]
            }
            for i, domain in enumerate(domains)
        }

        # Mock HTTP boundary for fast responses
        mock_response = Mock()
        mock_response.status_code = 200
        mocker.patch('requests.get', return_value=mock_response)

        # Act: Measure complete workflow execution time
        start_time = time.time()

        # Step 1: Prepare validation files
        validation_files = handler.prepare_http_validation(validation_data)

        # Step 2: Place validation files
        placement_result = handler.place_validation_files(validation_files, str(temp_directory))

        # Step 3: Verify all files
        for vf in validation_files:
            expected_content = '\n'.join(vf['content'])
            mock_response.text = expected_content
            verification_result = handler.verify_http_validation(vf['full_url'], expected_content)
            assert verification_result['accessible'] is True

        # Step 4: Clean up
        cleanup_result = handler.cleanup_validation_files(placement_result['files_created'])

        total_time = time.time() - start_time

        # Assert: Verify performance contract compliance
        assert total_time < 5.0  # Individual workflow should complete within 5 seconds
        assert placement_result['success'] is True
        assert cleanup_result['success'] is True
        assert len(validation_files) == 5
        assert len(placement_result['files_created']) == 5
        assert len(cleanup_result['files_removed']) == 5
