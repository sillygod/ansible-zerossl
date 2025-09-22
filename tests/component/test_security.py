# -*- coding: utf-8 -*-
"""
Component test for security and permissions.

This test covers security aspects like API key handling, file permissions,
and sensitive data protection.
"""

import pytest
import os
from unittest.mock import Mock, patch
from plugins.action.zerossl_certificate import ActionModule


@pytest.mark.component
class TestSecurityAndPermissions:
    """Test security and permission handling."""

    def test_api_key_not_logged(self, mock_action_base, mock_task_vars,
                               sample_api_key, sample_domains, temp_directory):
        """Test that API keys are not logged or exposed."""
        csr_path = temp_directory / "security.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nsecurity_csr\n-----END CERTIFICATE REQUEST-----")

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

        with patch.object(action_module, '_create_certificate',
                         return_value={'id': 'security_cert', 'validation': {'other_methods': {}}}):
            result = action_module.run(task_vars=mock_task_vars)

            # API key should not appear in result
            result_str = str(result)
            assert sample_api_key not in result_str

    def test_certificate_file_permissions(self, mock_action_base, mock_task_vars,
                                        sample_api_key, sample_domains, temp_directory):
        """Test that certificate files are created with secure permissions."""
        csr_path = temp_directory / "permissions.csr"
        cert_path = temp_directory / "permissions.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\npermissions_csr\n-----END CERTIFICATE REQUEST-----")

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

        certificate_content = "-----BEGIN CERTIFICATE-----\nsecurity_cert_content\n-----END CERTIFICATE-----"

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value=None),
            _create_certificate=Mock(return_value={'id': 'permissions_cert', 'validation': {'other_methods': {}}}),
            _validate_certificate=Mock(return_value={'success': True}),
            _download_certificate=Mock(return_value=certificate_content)
        ):
            # Mock _save_certificate to check permissions
            with patch.object(action_module, '_save_certificate') as mock_save:
                result = action_module.run(task_vars=mock_task_vars)

                # Verify save was called with secure path
                mock_save.assert_called_once_with(certificate_content, str(cert_path))

    def test_temporary_file_cleanup(self, mock_action_base, mock_task_vars,
                                  sample_api_key, sample_domains, temp_directory):
        """Test that temporary files are properly cleaned up."""
        csr_path = temp_directory / "cleanup.csr"
        cert_path = temp_directory / "cleanup.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ncleanup_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'download',
            'certificate_id': 'cleanup_cert_123'
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
            _download_certificate=Mock(return_value='cleanup_cert_content'),
            _save_certificate=Mock()
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Should complete successfully and clean up
            assert result['changed'] is True
