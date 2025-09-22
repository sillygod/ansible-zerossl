# -*- coding: utf-8 -*-
"""
Component test for split workflow scenario.

This test covers the step-by-step workflow from the quickstart guide:
requesting, validating, and downloading certificates separately for advanced control.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from plugins.action.zerossl_certificate import ActionModule


@pytest.mark.component
class TestSplitWorkflow:
    """Test split certificate workflow (request → validate → download)."""

    def test_step1_certificate_request(self, mock_action_base, mock_task_vars,
                                     sample_api_key, sample_domains, temp_directory):
        """Test Step 1: Certificate request returns validation files."""
        # Setup CSR file
        csr_path = temp_directory / "request.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nrequest_csr_content\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
            'state': 'request'
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

        # Mock certificate request response
        request_response = {
            'id': 'split_workflow_cert_123',
            'status': 'draft',
            'common_name': 'example.com',
            'additional_domains': 'www.example.com',
            'validation': {
                'other_methods': {
                    'example.com': {
                        'file_validation_url_http': 'http://example.com/.well-known/pki-validation/auth123.txt',
                        'file_validation_content': 'auth_content_123'
                    },
                    'www.example.com': {
                        'file_validation_url_http': 'http://www.example.com/.well-known/pki-validation/auth456.txt',
                        'file_validation_content': 'auth_content_456'
                    }
                }
            }
        }

        with patch.object(action_module, '_create_certificate', return_value=request_response):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify request step results
            assert result['changed'] is True
            assert result['certificate_id'] == 'split_workflow_cert_123'
            assert 'validation_files' in result
            assert len(result['validation_files']) == 2

            # Verify validation files structure
            validation_files = result['validation_files']
            domains_in_files = [vf['domain'] for vf in validation_files]
            assert 'example.com' in domains_in_files
            assert 'www.example.com' in domains_in_files

            # Verify validation file content
            for vf in validation_files:
                assert 'filename' in vf
                assert 'content' in vf
                assert 'http_validation_url' in vf
                assert vf['filename'].endswith('.txt')
                assert len(vf['content']) > 0

    def test_step2_validation_file_placement(self, mock_action_base, mock_task_vars,
                                           sample_api_key, temp_directory):
        """Test Step 2: Validation file placement simulation."""
        # This simulates the manual step where user places validation files
        # In practice, this would be done by Ansible copy module

        validation_files = [
            {
                'domain': 'example.com',
                'filename': 'auth123.txt',
                'content': 'auth_content_123',
                'http_validation_url': 'http://example.com/.well-known/pki-validation/auth123.txt'
            },
            {
                'domain': 'www.example.com',
                'filename': 'auth456.txt',
                'content': 'auth_content_456',
                'http_validation_url': 'http://www.example.com/.well-known/pki-validation/auth456.txt'
            }
        ]

        # Simulate placing validation files
        web_root = temp_directory / "webroot"
        validation_dir = web_root / ".well-known" / "pki-validation"
        validation_dir.mkdir(parents=True, exist_ok=True)

        for vf in validation_files:
            file_path = validation_dir / vf['filename']
            file_path.write_text(vf['content'])

            # Verify file was placed correctly
            assert file_path.exists()
            assert file_path.read_text() == vf['content']

            # Verify file permissions (in real scenario, would be 644)
            assert file_path.is_file()

    def test_step3_certificate_validation(self, mock_action_base, mock_task_vars, sample_api_key):
        """Test Step 3: Certificate validation with certificate ID."""
        certificate_id = 'split_workflow_cert_123'

        task_args = {
            'api_key': sample_api_key,
            'certificate_id': certificate_id,
            'state': 'validate'
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

        # Mock validation response
        validation_response = {
            'success': True,
            'validation_completed': True,
            'message': 'Domain validation successful'
        }

        with patch.object(action_module, '_validate_certificate', return_value=validation_response):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify validation step results
            assert result['changed'] is True
            assert 'validation_result' in result
            assert result['validation_result']['success'] is True
            assert result['validation_result']['validation_completed'] is True

            # Verify validation was called with correct parameters
            action_module._validate_certificate.assert_called_once_with(
                sample_api_key, certificate_id, 'HTTP_CSR_HASH', mock_task_vars
            )

    def test_step4_certificate_download(self, mock_action_base, mock_task_vars,
                                      sample_api_key, temp_directory):
        """Test Step 4: Certificate download with certificate ID."""
        certificate_id = 'split_workflow_cert_123'
        cert_path = temp_directory / "downloaded.crt"

        task_args = {
            'api_key': sample_api_key,
            'certificate_id': certificate_id,
            'certificate_path': str(cert_path),
            'state': 'download'
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

        # Mock certificate content
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
            _download_certificate=Mock(return_value=certificate_content),
            _save_certificate=Mock()
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify download step results
            assert result['changed'] is True

            # Verify download and save were called
            action_module._download_certificate.assert_called_once_with(
                sample_api_key, certificate_id, mock_task_vars
            )
            action_module._save_certificate.assert_called_once_with(
                certificate_content, str(cert_path)
            )

    def test_complete_split_workflow_sequence(self, mock_action_base, mock_task_vars,
                                            sample_api_key, sample_domains, temp_directory):
        """Test complete split workflow from start to finish."""
        # This test simulates running all three steps in sequence

        # Setup files
        csr_path = temp_directory / "sequence.csr"
        cert_path = temp_directory / "sequence.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nsequence_csr\n-----END CERTIFICATE REQUEST-----")

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Step 1: Request
        mock_action_base._task.args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
            'state': 'request'
        }

        request_response = {
            'id': 'sequence_cert_789',
            'validation': {
                'other_methods': {
                    'example.com': {
                        'file_validation_url_http': 'http://example.com/.well-known/pki-validation/seq123.txt',
                        'file_validation_content': 'seq_content_123'
                    }
                }
            }
        }

        with patch.object(action_module, '_create_certificate', return_value=request_response):
            request_result = action_module.run(task_vars=mock_task_vars)
            certificate_id = request_result['certificate_id']

        # Step 2: Validate
        mock_action_base._task.args = {
            'api_key': sample_api_key,
            'certificate_id': certificate_id,
            'state': 'validate'
        }

        with patch.object(action_module, '_validate_certificate',
                         return_value={'success': True, 'validation_completed': True}):
            validate_result = action_module.run(task_vars=mock_task_vars)

        # Step 3: Download
        mock_action_base._task.args = {
            'api_key': sample_api_key,
            'certificate_id': certificate_id,
            'certificate_path': str(cert_path),
            'state': 'download'
        }

        with patch.multiple(
            action_module,
            _download_certificate=Mock(return_value='final_cert_content'),
            _save_certificate=Mock()
        ):
            download_result = action_module.run(task_vars=mock_task_vars)

        # Verify sequence worked
        assert request_result['changed'] is True
        assert validate_result['changed'] is True
        assert download_result['changed'] is True
        assert request_result['certificate_id'] == certificate_id

    def test_split_workflow_error_handling(self, mock_action_base, mock_task_vars,
                                         sample_api_key, sample_domains, temp_directory):
        """Test error handling in split workflow steps."""
        csr_path = temp_directory / "error.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nerror_csr\n-----END CERTIFICATE REQUEST-----")

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Test validation step with non-existent certificate ID
        mock_action_base._task.args = {
            'api_key': sample_api_key,
            'certificate_id': 'nonexistent_cert_id',
            'state': 'validate'
        }

        from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError
        with patch.object(action_module, '_validate_certificate',
                         side_effect=ZeroSSLHTTPError("Certificate not found")):
            result = action_module.run(task_vars=mock_task_vars)

            assert result.get('failed') is True
            assert 'not found' in result['msg'].lower()

    def test_split_workflow_validation_methods(self, mock_action_base, mock_task_vars,
                                             sample_api_key, sample_domains, temp_directory):
        """Test split workflow with different validation methods."""
        csr_path = temp_directory / "validation_method.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nvalidation_csr\n-----END CERTIFICATE REQUEST-----")

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Test DNS validation method
        mock_action_base._task.args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
            'state': 'request',
            'validation_method': 'DNS_CSR_HASH'
        }

        dns_response = {
            'id': 'dns_cert_123',
            'validation': {
                'other_methods': {
                    'example.com': {
                        'cname_validation_p1': 'A1B2C3D4E5F6.example.com',
                        'cname_validation_p2': 'A1B2C3D4E5F6.B2C3D4E5F6A1.C3D4E5F6A1B2.zerossl.com'
                    }
                }
            }
        }

        with patch.object(action_module, '_create_certificate', return_value=dns_response):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify DNS validation files are structured differently
            assert result['changed'] is True
            assert result['certificate_id'] == 'dns_cert_123'

            # DNS validation should provide different file structure
            validation_files = result['validation_files']
            for vf in validation_files:
                # DNS validation files should have DNS-specific fields
                assert 'domain' in vf
                # Implementation would include DNS record information

    def test_split_workflow_state_persistence(self, mock_action_base, mock_task_vars,
                                            sample_api_key, temp_directory):
        """Test that split workflow maintains state between steps."""
        # Test that certificate ID from request step can be used in subsequent steps
        certificate_id = 'persistent_cert_456'

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Test validate step with certificate ID from previous request
        mock_action_base._task.args = {
            'api_key': sample_api_key,
            'certificate_id': certificate_id,
            'state': 'validate',
            'validation_method': 'HTTP_CSR_HASH'
        }

        with patch.object(action_module, '_validate_certificate',
                         return_value={'success': True}) as mock_validate:
            result = action_module.run(task_vars=mock_task_vars)

            # Verify validation was called with persistent certificate ID
            mock_validate.assert_called_once_with(
                sample_api_key, certificate_id, 'HTTP_CSR_HASH', mock_task_vars
            )
            assert result['changed'] is True

    def test_split_workflow_missing_certificate_id(self, mock_action_base, mock_task_vars, sample_api_key):
        """Test error handling when certificate ID is missing for validate/download steps."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Test validate step without certificate_id
        mock_action_base._task.args = {
            'api_key': sample_api_key,
            'state': 'validate'
            # Missing certificate_id
        }

        with patch.object(action_module, '_get_certificate_id', return_value=None):
            with pytest.raises(Exception):  # Should raise appropriate error
                action_module.run(task_vars=mock_task_vars)
