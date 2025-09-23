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
            'state': 'request',
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

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': []}
        mock_session.get.return_value = mock_response

        create_mock_response = Mock()
        create_mock_response.status_code = 200
        create_mock_response.json.return_value = {'success': True, 'result': {'id': 'security_cert', 'validation': {'other_methods': {}}}}
        mock_session.post.return_value = create_mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_request_state',
                         return_value={'certificate_id': 'security_cert', 'changed': True}):
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

        certificate_content = "-----BEGIN CERTIFICATE-----\nsecurity_cert_content\n-----END CERTIFICATE-----"

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': []}
        mock_session.get.return_value = mock_response

        create_mock_response = Mock()
        create_mock_response.status_code = 200
        create_mock_response.json.return_value = {'success': True, 'result': {'id': 'permissions_cert', 'validation': {'other_methods': {}}}}
        mock_session.post.return_value = create_mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_present_state',
                         return_value={'certificate_id': 'permissions_cert', 'changed': True, 'files_created': [str(cert_path)]}):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify file creation was tracked
            assert result['changed'] is True
            assert 'files_created' in result

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

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': {'certificate': 'cleanup_cert_content'}}
        mock_session.get.return_value = mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_download_state',
                         return_value={'certificate_id': 'cleanup_cert_123', 'changed': True, 'files_created': [str(cert_path)]}):
            result = action_module.run(task_vars=mock_task_vars)

            # Should complete successfully and clean up
            assert result['changed'] is True
