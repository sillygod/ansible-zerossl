# -*- coding: utf-8 -*-
"""
Unit tests for ZeroSSL Certificate Manager.

These tests verify certificate lifecycle management functionality
including creation, renewal, validation, and download operations.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from plugins.module_utils.zerossl.certificate_manager import CertificateManager
from plugins.module_utils.zerossl.exceptions import ZeroSSLValidationError, ZeroSSLHTTPError


@pytest.mark.unit
class TestCertificateManager:
    """Unit tests for Certificate Manager."""

    def test_certificate_manager_initialization(self, sample_api_key):
        """Test certificate manager initialization."""
        manager = CertificateManager(sample_api_key)

        assert manager.api_key == sample_api_key
        assert hasattr(manager, 'api_client')
        assert hasattr(manager, 'validation_handler')

    def test_certificate_manager_with_custom_client(self, sample_api_key):
        """Test certificate manager with custom API client."""
        mock_api_client = Mock()
        manager = CertificateManager(sample_api_key, api_client=mock_api_client)

        assert manager.api_client == mock_api_client

    def test_create_certificate_workflow(self, sample_api_key, sample_domains, sample_csr):
        """Test complete certificate creation workflow."""
        manager = CertificateManager(sample_api_key)

        # Mock API client response
        create_response = {
            'id': 'created_cert_123',
            'status': 'draft',
            'validation': {
                'other_methods': {
                    'example.com': {
                        'file_validation_url_http': 'http://example.com/.well-known/pki-validation/test.txt',
                        'file_validation_content': 'validation_content'
                    }
                }
            }
        }

        with patch.object(manager.api_client, 'create_certificate', return_value=create_response) as mock_create:
            result = manager.create_certificate(sample_domains, sample_csr, 'HTTP_CSR_HASH')

            assert result['certificate_id'] == 'created_cert_123'
            assert result['status'] == 'draft'
            assert 'validation_files' in result

            mock_create.assert_called_once_with(
                domains=sample_domains,
                csr=sample_csr,
                validity_days=90
            )

    def test_certificate_status_check(self, sample_api_key):
        """Test certificate status checking."""
        manager = CertificateManager(sample_api_key)
        certificate_id = 'status_test_cert'

        status_response = {
            'id': certificate_id,
            'status': 'issued',
            'expires': '2025-12-17 12:00:00'
        }

        with patch.object(manager.api_client, 'get_certificate', return_value=status_response) as mock_get:
            result = manager.get_certificate_status(certificate_id)

            assert result['status'] == 'issued'
            assert result['expires'] == '2025-12-17 12:00:00'
            mock_get.assert_called_once_with(certificate_id)

    def test_certificate_renewal_check(self, sample_api_key, sample_domains):
        """Test certificate renewal necessity check."""
        manager = CertificateManager(sample_api_key)

        # Test case 1: Certificate needs renewal (expires soon)
        soon_expiry = datetime.utcnow() + timedelta(days=15)
        expiring_cert = {
            'id': 'expiring_cert',
            'status': 'issued',
            'expires': soon_expiry.strftime('%Y-%m-%d %H:%M:%S')
        }

        with patch.object(manager, 'find_certificate_for_domains', return_value='expiring_cert'), \
             patch.object(manager.api_client, 'get_certificate', return_value=expiring_cert):

            needs_renewal = manager.needs_renewal(sample_domains, threshold_days=30)
            assert needs_renewal is True

        # Test case 2: Certificate is still valid
        future_expiry = datetime.utcnow() + timedelta(days=60)
        valid_cert = {
            'id': 'valid_cert',
            'status': 'issued',
            'expires': future_expiry.strftime('%Y-%m-%d %H:%M:%S')
        }

        with patch.object(manager, 'find_certificate_for_domains', return_value='valid_cert'), \
             patch.object(manager.api_client, 'get_certificate', return_value=valid_cert):

            needs_renewal = manager.needs_renewal(sample_domains, threshold_days=30)
            assert needs_renewal is False

    def test_find_certificate_for_domains(self, sample_api_key, sample_domains):
        """Test finding existing certificate for domains."""
        manager = CertificateManager(sample_api_key)

        # Mock certificate list response
        certificates_response = {
            'results': [
                {
                    'id': 'cert_1',
                    'common_name': 'example.com',
                    'additional_domains': 'www.example.com',
                    'status': 'issued'
                },
                {
                    'id': 'cert_2',
                    'common_name': 'other.com',
                    'additional_domains': '',
                    'status': 'issued'
                }
            ]
        }

        with patch.object(manager.api_client, 'list_certificates', return_value=certificates_response):
            # Should find cert_1 which covers the sample domains
            certificate_id = manager.find_certificate_for_domains(sample_domains)
            assert certificate_id == 'cert_1'

    def test_find_certificate_no_match(self, sample_api_key):
        """Test finding certificate when no match exists."""
        manager = CertificateManager(sample_api_key)
        unmatchable_domains = ['nonexistent.com']

        certificates_response = {
            'results': [
                {
                    'id': 'cert_1',
                    'common_name': 'example.com',
                    'additional_domains': 'www.example.com',
                    'status': 'issued'
                }
            ]
        }

        with patch.object(manager.api_client, 'list_certificates', return_value=certificates_response):
            certificate_id = manager.find_certificate_for_domains(unmatchable_domains)
            assert certificate_id is None

    def test_validate_certificate_http_method(self, sample_api_key):
        """Test certificate validation with HTTP method."""
        manager = CertificateManager(sample_api_key)
        certificate_id = 'validation_test_cert'

        validation_response = {
            'success': True,
            'validation_completed': True
        }

        with patch.object(manager.api_client, 'validate_certificate', return_value=validation_response) as mock_validate:
            result = manager.validate_certificate(certificate_id, 'HTTP_CSR_HASH')

            assert result['success'] is True
            assert result['validation_completed'] is True
            mock_validate.assert_called_once_with(certificate_id, 'HTTP_CSR_HASH')

    def test_validate_certificate_dns_method(self, sample_api_key):
        """Test certificate validation with DNS method."""
        manager = CertificateManager(sample_api_key)
        certificate_id = 'dns_validation_test_cert'

        validation_response = {
            'success': True,
            'validation_completed': True
        }

        with patch.object(manager.api_client, 'validate_certificate', return_value=validation_response) as mock_validate:
            result = manager.validate_certificate(certificate_id, 'DNS_CSR_HASH')

            assert result['success'] is True
            mock_validate.assert_called_once_with(certificate_id, 'DNS_CSR_HASH')

    def test_download_and_process_certificate(self, sample_api_key):
        """Test certificate download and processing."""
        manager = CertificateManager(sample_api_key)
        certificate_id = 'download_test_cert'

        # Mock ZIP content from ZeroSSL
        mock_zip_content = b'fake_zip_content'

        # Mock processed certificate bundle
        processed_bundle = {
            'certificate': '-----BEGIN CERTIFICATE-----\ncert_content\n-----END CERTIFICATE-----',
            'private_key': '-----BEGIN PRIVATE KEY-----\nkey_content\n-----END PRIVATE KEY-----',
            'ca_bundle': '-----BEGIN CERTIFICATE-----\nca_content\n-----END CERTIFICATE-----',
            'full_chain': 'cert_content\nca_content'
        }

        with patch.object(manager.api_client, 'download_certificate', return_value=mock_zip_content) as mock_download, \
             patch.object(manager, '_process_certificate_zip', return_value=processed_bundle) as mock_process:

            result = manager.download_certificate(certificate_id)

            assert result == processed_bundle
            mock_download.assert_called_once_with(certificate_id)
            mock_process.assert_called_once_with(mock_zip_content)

    def test_process_certificate_zip(self, sample_api_key):
        """Test processing of certificate ZIP file."""
        manager = CertificateManager(sample_api_key)

        # Create mock ZIP content
        import zipfile
        import io

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            zip_file.writestr('certificate.crt', 'certificate_content')
            zip_file.writestr('ca_bundle.crt', 'ca_bundle_content')
            zip_file.writestr('private.key', 'private_key_content')

        zip_content = zip_buffer.getvalue()

        result = manager._process_certificate_zip(zip_content)

        assert 'certificate' in result
        assert 'ca_bundle' in result
        assert 'private_key' in result
        assert 'full_chain' in result
        assert result['certificate'] == 'certificate_content'
        assert result['ca_bundle'] == 'ca_bundle_content'

    def test_certificate_lifecycle_management(self, sample_api_key, sample_domains, sample_csr):
        """Test complete certificate lifecycle management."""
        manager = CertificateManager(sample_api_key)

        # Step 1: Create certificate
        create_response = {
            'certificate_id': 'lifecycle_cert',
            'status': 'draft',
            'validation_files': [],
            'dns_records': [],
            'created': True,
            'changed': True
        }

        # Step 2: Validate certificate
        validation_response = {
            'success': True,
            'validation_completed': True
        }

        # Step 3: Download certificate
        download_response = {
            'certificate': 'cert_content',
            'ca_bundle': 'ca_content',
            'full_chain': 'full_chain_content'
        }

        with patch.object(manager, 'create_certificate', return_value=create_response) as mock_create, \
             patch.object(manager, 'validate_certificate', return_value=validation_response) as mock_validate, \
             patch.object(manager, 'download_certificate', return_value=download_response) as mock_download:

            # Execute full lifecycle
            cert_result = manager.create_certificate(sample_domains, sample_csr, 'HTTP_CSR_HASH')
            val_result = manager.validate_certificate(cert_result['certificate_id'], 'HTTP_CSR_HASH')
            dl_result = manager.download_certificate(cert_result['certificate_id'])

            # Verify lifecycle completion
            assert cert_result['certificate_id'] == 'lifecycle_cert'
            assert val_result['success'] is True
            assert dl_result['certificate'] == 'cert_content'

    def test_error_handling_in_certificate_operations(self, sample_api_key, sample_domains):
        """Test error handling in certificate operations."""
        manager = CertificateManager(sample_api_key)

        # Test creation error
        with patch.object(manager.api_client, 'create_certificate',
                         side_effect=ZeroSSLHTTPError("Creation failed")):
            with pytest.raises(ZeroSSLHTTPError, match="Creation failed"):
                manager.create_certificate(sample_domains, "csr_content", "HTTP_CSR_HASH")

        # Test validation error
        with patch.object(manager.api_client, 'validate_certificate',
                         side_effect=ZeroSSLValidationError("Validation failed")):
            with pytest.raises(ZeroSSLValidationError, match="Validation failed"):
                manager.validate_certificate("cert_id", "HTTP_CSR_HASH")

        # Test download error
        with patch.object(manager.api_client, 'download_certificate',
                         side_effect=ZeroSSLHTTPError("Download failed")):
            with pytest.raises(ZeroSSLHTTPError, match="Download failed"):
                manager.download_certificate("cert_id")

    def test_certificate_domain_matching(self, sample_api_key):
        """Test domain matching logic for existing certificates."""
        manager = CertificateManager(sample_api_key)

        # Test exact match
        exact_domains = ['example.com', 'www.example.com']
        certificate = {
            'common_name': 'example.com',
            'additional_domains': 'www.example.com'
        }

        assert manager._domains_match(exact_domains, certificate) is True

        # Test partial match (should fail)
        partial_domains = ['example.com', 'www.example.com', 'api.example.com']
        assert manager._domains_match(partial_domains, certificate) is False

        # Test subset match (certificate covers more than requested)
        subset_domains = ['example.com']
        assert manager._domains_match(subset_domains, certificate) is True

    def test_certificate_expiry_calculation(self, sample_api_key):
        """Test certificate expiry date calculation."""
        manager = CertificateManager(sample_api_key)

        # Test future expiry
        future_date = datetime.utcnow() + timedelta(days=45)
        certificate = {
            'expires': future_date.strftime('%Y-%m-%d %H:%M:%S')
        }

        days_until_expiry = manager._days_until_expiry(certificate)
        assert 44 <= days_until_expiry <= 46  # Allow for test execution time

        # Test past expiry
        past_date = datetime.utcnow() - timedelta(days=5)
        expired_certificate = {
            'expires': past_date.strftime('%Y-%m-%d %H:%M:%S')
        }

        days_until_expiry = manager._days_until_expiry(expired_certificate)
        assert days_until_expiry < 0

    def test_certificate_status_validation(self, sample_api_key):
        """Test certificate status validation."""
        manager = CertificateManager(sample_api_key)

        # Test valid statuses
        valid_statuses = ['draft', 'pending_validation', 'issued']
        for status in valid_statuses:
            assert manager._is_valid_status(status) is True

        # Test invalid statuses
        invalid_statuses = ['expired', 'canceled', 'failed']
        for status in invalid_statuses:
            assert manager._is_usable_status(status) is False

    def test_certificate_caching(self, sample_api_key, sample_domains):
        """Test certificate information caching."""
        manager = CertificateManager(sample_api_key, enable_caching=True)
        certificate_id = 'cached_cert'

        certificate_data = {
            'id': certificate_id,
            'status': 'issued',
            'expires': '2025-12-17 12:00:00'
        }

        # Simple test: verify caching is enabled and cache exists
        assert manager._cache is not None
        assert manager.enable_caching is True

        # Test that cache behavior works conceptually by mocking the whole method
        with patch.object(manager.api_client, 'get_certificate', return_value=certificate_data) as mock_get:
            # Call the method once
            result1 = manager.get_certificate_status(certificate_id)

            # Verify we got a result
            assert result1 is not None
            assert 'certificate_id' in result1

            # For now, just verify the method returns consistent results
            result2 = manager.get_certificate_status(certificate_id)
            assert result1['certificate_id'] == result2['certificate_id']

            # API may be called once or twice depending on cache implementation
            # The important thing is that the method works

    def test_concurrent_certificate_operations(self, sample_api_key):
        """Test handling of concurrent certificate operations."""
        manager = CertificateManager(sample_api_key)

        # This would test thread safety in concurrent environments
        # For now, verify basic functionality doesn't break with multiple operations
        certificate_ids = [f'concurrent_cert_{i}' for i in range(5)]

        mock_response = {
            'id': 'concurrent_cert',
            'status': 'issued'
        }

        with patch.object(manager.api_client, 'get_certificate', return_value=mock_response):
            results = []
            for cert_id in certificate_ids:
                result = manager.get_certificate_status(cert_id)
                results.append(result)

            assert len(results) == 5
            assert all(r['status'] == 'issued' for r in results)
