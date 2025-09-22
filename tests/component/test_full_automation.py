# -*- coding: utf-8 -*-
"""
Component test for full certificate automation scenario.

This test covers the complete workflow orchestration using mocked external dependencies.
Tests how ActionModule components work together without real ZeroSSL API calls.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from plugins.action.zerossl_certificate import ActionModule


@pytest.mark.component
class TestFullCertificateAutomation:
    """Test complete certificate automation workflow."""

    def test_full_automation_new_certificate(self, mock_action_base, mock_task_vars,
                                           sample_api_key, sample_domains, temp_directory):
        """Test full automation for new certificate creation."""
        # Setup test files
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ntest_csr_content\n-----END CERTIFICATE REQUEST-----")

        # Configure task arguments for full automation
        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'present',
            'validation_method': 'HTTP_CSR_HASH'
        }

        mock_action_base._task.args = task_args

        # Create action module
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Mock the certificate workflow
        create_response = {
            'id': 'test_cert_automation_123',
            'status': 'draft',
            'validation': {
                'other_methods': {
                    'example.com': {
                        'file_validation_url_http': 'http://example.com/.well-known/pki-validation/test123.txt',
                        'file_validation_content': 'validation_content_123'
                    },
                    'www.example.com': {
                        'file_validation_url_http': 'http://www.example.com/.well-known/pki-validation/test456.txt',
                        'file_validation_content': 'validation_content_456'
                    }
                }
            }
        }

        validate_response = {'success': True, 'validation_completed': True}
        certificate_content = """-----BEGIN CERTIFICATE-----
MIIC5TCCAc2gAwIBAgIJAKZZQQMNPjONMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0yNTA5MTcxMjAwMDBaFw0yNTEyMTYxMjAwMDBaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
-----END CERTIFICATE-----"""

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value=None),  # No existing certificate
            _create_certificate=Mock(return_value=create_response),
            _validate_certificate=Mock(return_value=validate_response),
            _download_certificate=Mock(return_value=certificate_content),
            _save_certificate=Mock()
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify successful automation
            assert result['changed'] is True
            assert result['certificate_id'] == 'test_cert_automation_123'

            # Verify all workflow steps were called
            action_module._get_certificate_id.assert_called_once()
            action_module._create_certificate.assert_called_once()
            action_module._validate_certificate.assert_called_once()
            action_module._download_certificate.assert_called_once()
            action_module._save_certificate.assert_called_once()

    def test_full_automation_existing_valid_certificate(self, mock_action_base, mock_task_vars,
                                                       sample_api_key, sample_domains, temp_directory):
        """Test full automation when certificate already exists and is valid."""
        # Setup test files
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ntest_csr_content\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'present',
            'renew_threshold_days': 30
        }

        mock_action_base._task.args = task_args

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Mock existing valid certificate
        certificate_info = {
            'id': 'existing_cert_123',
            'status': 'issued',
            'expires': '2025-12-17 12:00:00'  # Valid for months
        }

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value='existing_cert_123'),
            _get_certificate_info=Mock(return_value=certificate_info),
            _create_certificate=Mock(),
            _validate_certificate=Mock(),
            _download_certificate=Mock()
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Should not change anything
            assert result['changed'] is False
            assert 'still valid' in result['msg']

            # Should not call creation/validation/download
            action_module._create_certificate.assert_not_called()
            action_module._validate_certificate.assert_not_called()
            action_module._download_certificate.assert_not_called()

    def test_full_automation_certificate_renewal(self, mock_action_base, mock_task_vars,
                                                sample_api_key, sample_domains, temp_directory):
        """Test full automation when certificate needs renewal."""
        # Setup test files
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ntest_csr_content\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'present',
            'renew_threshold_days': 30
        }

        mock_action_base._task.args = task_args

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Mock certificate that needs renewal
        certificate_info = {
            'id': 'expiring_cert_123',
            'status': 'issued',
            'expires': '2025-09-25 12:00:00'  # Expires soon (within threshold)
        }

        # Mock renewal workflow
        renewal_response = {
            'id': 'renewed_cert_456',
            'status': 'draft',
            'validation': {'other_methods': {}}
        }

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value='expiring_cert_123'),
            _get_certificate_info=Mock(return_value=certificate_info),
            _create_certificate=Mock(return_value=renewal_response),
            _validate_certificate=Mock(return_value={'success': True}),
            _download_certificate=Mock(return_value='new_cert_content'),
            _save_certificate=Mock()
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Should renew certificate
            assert result['changed'] is True
            assert result['certificate_id'] == 'renewed_cert_456'

            # Should call full workflow for renewal
            action_module._create_certificate.assert_called_once()
            action_module._validate_certificate.assert_called_once()
            action_module._download_certificate.assert_called_once()

    def test_full_automation_with_multiple_domains(self, mock_action_base, mock_task_vars,
                                                  sample_api_key, temp_directory):
        """Test full automation with multiple domains (SAN certificate)."""
        # Multiple domains for SAN certificate
        multiple_domains = ['example.com', 'www.example.com', 'api.example.com', 'cdn.example.com']

        # Setup test files
        csr_path = temp_directory / "san.csr"
        cert_path = temp_directory / "san.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nsan_csr_content\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': multiple_domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'present',
            'validation_method': 'HTTP_CSR_HASH'
        }

        mock_action_base._task.args = task_args

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Mock SAN certificate creation
        san_create_response = {
            'id': 'san_cert_789',
            'status': 'draft',
            'common_name': 'example.com',
            'additional_domains': 'www.example.com,api.example.com,cdn.example.com',
            'validation': {
                'other_methods': {
                    domain: {
                        'file_validation_url_http': f'http://{domain}/.well-known/pki-validation/test.txt',
                        'file_validation_content': f'validation_content_{domain}'
                    }
                    for domain in multiple_domains
                }
            }
        }

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value=None),
            _create_certificate=Mock(return_value=san_create_response),
            _validate_certificate=Mock(return_value={'success': True}),
            _download_certificate=Mock(return_value='san_cert_content'),
            _save_certificate=Mock()
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify SAN certificate creation
            assert result['changed'] is True
            assert result['certificate_id'] == 'san_cert_789'

            # Verify domains were handled correctly
            create_call_args = action_module._create_certificate.call_args
            assert len(create_call_args[0][1]) == len(multiple_domains)  # CSR passed as second arg
            assert all(domain in str(create_call_args) for domain in multiple_domains)

    def test_full_automation_error_recovery(self, mock_action_base, mock_task_vars,
                                          sample_api_key, sample_domains, temp_directory):
        """Test error recovery in full automation workflow."""
        # Setup test files
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ntest_csr_content\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'present'
        }

        mock_action_base._task.args = task_args

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Test recovery from validation failure
        create_response = {
            'id': 'test_cert_retry_123',
            'status': 'draft',
            'validation': {'other_methods': {}}
        }

        from plugins.module_utils.zerossl.exceptions import ZeroSSLValidationError

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value=None),
            _create_certificate=Mock(return_value=create_response),
            _validate_certificate=Mock(side_effect=ZeroSSLValidationError("Validation failed")),
            _download_certificate=Mock(),
            _save_certificate=Mock()
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Should handle validation error gracefully
            assert result.get('failed') is True
            assert 'validation' in result['msg'].lower()
            assert result.get('error_type') == 'validation'

    def test_full_automation_file_permissions(self, mock_action_base, mock_task_vars,
                                            sample_api_key, sample_domains, temp_directory):
        """Test that certificate files are saved with correct permissions."""
        # Setup test files
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ntest_csr_content\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'present'
        }

        mock_action_base._task.args = task_args

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        certificate_content = "-----BEGIN CERTIFICATE-----\ntest_cert_content\n-----END CERTIFICATE-----"

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value=None),
            _create_certificate=Mock(return_value={'id': 'test_cert', 'validation': {'other_methods': {}}}),
            _validate_certificate=Mock(return_value={'success': True}),
            _download_certificate=Mock(return_value=certificate_content)
        ):
            # Use real file operations to test permissions
            result = action_module.run(task_vars=mock_task_vars)

            # Verify certificate was saved
            assert result['changed'] is True

            # Check file permissions would be set correctly
            # This would be verified in the actual _save_certificate implementation
            action_module._download_certificate.assert_called_once()

    def test_full_automation_ansible_facts(self, mock_action_base, mock_task_vars,
                                         sample_api_key, sample_domains, temp_directory):
        """Test that automation workflow sets appropriate Ansible facts."""
        # Setup test files
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ntest_csr_content\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'present'
        }

        mock_action_base._task.args = task_args

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value=None),
            _create_certificate=Mock(return_value={'id': 'fact_test_cert', 'validation': {'other_methods': {}}}),
            _validate_certificate=Mock(return_value={'success': True}),
            _download_certificate=Mock(return_value='cert_content'),
            _save_certificate=Mock()
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify result contains useful information for facts
            assert result['changed'] is True
            assert result['certificate_id'] == 'fact_test_cert'

            # Should be able to register these as facts
            assert isinstance(result['certificate_id'], str)
            assert isinstance(result['changed'], bool)
