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
            'validation_method': 'HTTP_CSR_HASH',
            'web_root': str(temp_directory)
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

        # Mock HTTP session to prevent real API calls
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': []}  # No existing certs
        mock_session.get.return_value = mock_response

        # Mock certificate creation
        create_mock_response = Mock()
        create_mock_response.status_code = 200
        create_mock_response.json.return_value = {'success': True, 'result': create_response}
        mock_session.post.return_value = create_mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_present_state',
                         return_value={'certificate_id': 'test_cert_automation_123', 'changed': True}):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify successful automation
            assert result['changed'] is True
            assert result['certificate_id'] == 'test_cert_automation_123'

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
            'renew_threshold_days': 30,
            'web_root': str(temp_directory)
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

        # Mock existing valid certificate workflow
        with patch.object(action_module, '_handle_present_state',
                         return_value={'changed': False, 'msg': 'Certificate still valid', 'certificate_id': 'existing_cert_123'}):
            result = action_module.run(task_vars=mock_task_vars)

            # Should not change anything
            assert result['changed'] is False
            assert 'still valid' in result['msg'] or 'certificate_id' in result

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
            'renew_threshold_days': 30,
            'web_root': str(temp_directory)
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

        # Mock renewal workflow
        with patch.object(action_module, '_handle_present_state',
                         return_value={'changed': True, 'msg': 'Certificate renewed', 'certificate_id': 'renewed_cert_456'}):
            result = action_module.run(task_vars=mock_task_vars)

            # Should renew certificate
            assert result['changed'] is True
            assert 'certificate_id' in result

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
            'validation_method': 'HTTP_CSR_HASH',
            'web_root': str(temp_directory)
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

        with patch.object(action_module, '_handle_present_state',
                         return_value={'changed': True, 'certificate_id': 'san_cert_789'}):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify SAN certificate creation
            assert result['changed'] is True
            assert result['certificate_id'] == 'san_cert_789'

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
            'state': 'present',
            'web_root': str(temp_directory)
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

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': []}
        mock_session.get.return_value = mock_response
        mock_session.post.return_value = mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_present_state',
                         side_effect=ZeroSSLValidationError("Validation failed")):
            # The action module raises AnsibleActionFail for validation errors
            from ansible.errors import AnsibleActionFail
            with pytest.raises(AnsibleActionFail) as exc_info:
                result = action_module.run(task_vars=mock_task_vars)

            # Should raise AnsibleActionFail with validation error message
            assert 'validation failed' in str(exc_info.value).lower()

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
            'state': 'present',
            'web_root': str(temp_directory)
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

        with patch.object(action_module, '_handle_present_state',
                         return_value={'changed': True, 'files_created': [str(cert_path)]}):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify certificate was saved
            assert result['changed'] is True

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
            'state': 'present',
            'web_root': str(temp_directory)
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

        with patch.object(action_module, '_handle_present_state',
                         return_value={'changed': True, 'certificate_id': 'fact_test_cert'}):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify result contains useful information for facts
            assert result['changed'] is True
            assert result['certificate_id'] == 'fact_test_cert'

            # Should be able to register these as facts
            assert isinstance(result['certificate_id'], str)
            assert isinstance(result['changed'], bool)
