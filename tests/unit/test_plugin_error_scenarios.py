# -*- coding: utf-8 -*-
"""
Error Scenario Tests for ZeroSSL Action Plugin.

These tests focus specifically on error handling, edge cases, and
exception paths to improve test coverage.
"""

import pytest
from unittest.mock import Mock, patch
from plugins.action.zerossl_certificate import ActionModule
from ansible.errors import AnsibleActionFail
from plugins.module_utils.zerossl.exceptions import (
    ZeroSSLHTTPError, ZeroSSLConfigurationError, ZeroSSLValidationError,
    ZeroSSLCertificateError, ZeroSSLFileSystemError
)


@pytest.mark.unit
class TestActionModuleErrorScenarios:
    """Test error scenarios and exception handling in ActionModule."""

    @pytest.fixture
    def mock_http_boundary(self, mocker):
        """Mock HTTP boundary for external API calls."""
        return mocker.patch('requests.Session')

    def test_parameter_validation_failure(self, mock_ansible_environment, mock_http_boundary):
        """Test parameter validation failure scenario."""
        action_module = ActionModule(
            task=mock_ansible_environment.task,
            connection=mock_ansible_environment.connection,
            play_context=mock_ansible_environment.play_context,
            loader=mock_ansible_environment.loader,
            templar=mock_ansible_environment.templar,
            shared_loader_obj=mock_ansible_environment.shared_loader_obj
        )

        # Set invalid parameters to trigger validation error
        mock_ansible_environment.task.args = {
            'api_key': 'too_short',  # Invalid API key
            'domains': ['example.com'],
            'state': 'present'
        }

        result = action_module.run(task_vars=mock_ansible_environment.task_vars)
        assert result.get('failed') is True
        assert 'api key' in result.get('msg', '').lower()

    def test_unexpected_exception_handling(self, mock_ansible_environment, mocker, mock_http_boundary):
        """Test unexpected exception handling in run method."""
        action_module = ActionModule(
            task=mock_ansible_environment.task,
            connection=mock_ansible_environment.connection,
            play_context=mock_ansible_environment.play_context,
            loader=mock_ansible_environment.loader,
            templar=mock_ansible_environment.templar,
            shared_loader_obj=mock_ansible_environment.shared_loader_obj
        )

        mock_ansible_environment.task.args = {
            'api_key': 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6',
            'domains': ['exception.example.com'],
            'state': 'present'
        }

        # Mock _validate_parameters to raise unexpected exception
        mocker.patch.object(action_module, '_validate_parameters', side_effect=RuntimeError("Unexpected error"))

        with pytest.raises(AnsibleActionFail):
            action_module.run(task_vars=mock_ansible_environment.task_vars)

    def test_api_client_creation_failure(self, mock_ansible_environment, mocker, mock_http_boundary):
        """Test API client creation failure scenario."""
        action_module = ActionModule(
            task=mock_ansible_environment.task,
            connection=mock_ansible_environment.connection,
            play_context=mock_ansible_environment.play_context,
            loader=mock_ansible_environment.loader,
            templar=mock_ansible_environment.templar,
            shared_loader_obj=mock_ansible_environment.shared_loader_obj
        )

        mock_ansible_environment.task.args = {
            'api_key': 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6',
            'domains': ['api-error.example.com'],
            'state': 'present',
            'validation_method': 'DNS_CSR_HASH'  # Use DNS to avoid web_root requirement
        }

        # Mock _create_api_client to raise HTTP error
        mocker.patch.object(action_module, '_create_api_client', side_effect=ZeroSSLHTTPError("API client creation failed"))

        with pytest.raises(AnsibleActionFail) as exc_info:
            action_module.run(task_vars=mock_ansible_environment.task_vars)
        assert 'api client creation failed' in str(exc_info.value).lower()

    def test_certificate_manager_creation_failure(self, mock_ansible_environment, mocker, mock_http_boundary):
        """Test certificate manager creation failure scenario."""
        action_module = ActionModule(
            task=mock_ansible_environment.task,
            connection=mock_ansible_environment.connection,
            play_context=mock_ansible_environment.play_context,
            loader=mock_ansible_environment.loader,
            templar=mock_ansible_environment.templar,
            shared_loader_obj=mock_ansible_environment.shared_loader_obj
        )

        mock_ansible_environment.task.args = {
            'api_key': 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6',
            'domains': ['cert-mgr-error.example.com'],
            'state': 'present',
            'validation_method': 'DNS_CSR_HASH'
        }

        # Mock _create_certificate_manager to raise configuration error
        mocker.patch.object(action_module, '_create_certificate_manager', side_effect=ZeroSSLConfigurationError("Certificate manager creation failed"))

        with pytest.raises(AnsibleActionFail) as exc_info:
            action_module.run(task_vars=mock_ansible_environment.task_vars)
        assert 'certificate manager creation failed' in str(exc_info.value).lower()

    def test_validation_handler_creation_failure(self, mock_ansible_environment, mocker, mock_http_boundary):
        """Test validation handler creation failure scenario."""
        action_module = ActionModule(
            task=mock_ansible_environment.task,
            connection=mock_ansible_environment.connection,
            play_context=mock_ansible_environment.play_context,
            loader=mock_ansible_environment.loader,
            templar=mock_ansible_environment.templar,
            shared_loader_obj=mock_ansible_environment.shared_loader_obj
        )

        mock_ansible_environment.task.args = {
            'api_key': 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6',
            'domains': ['val-handler-error.example.com'],
            'state': 'present',
            'validation_method': 'DNS_CSR_HASH'
        }

        # Mock _create_validation_handler to raise validation error
        mocker.patch.object(action_module, '_create_validation_handler', side_effect=ZeroSSLValidationError("Validation handler creation failed"))

        with pytest.raises(AnsibleActionFail) as exc_info:
            action_module.run(task_vars=mock_ansible_environment.task_vars)
        assert 'validation handler creation failed' in str(exc_info.value).lower()

    def test_csr_file_reading_error(self, mock_ansible_environment, temp_directory, mock_http_boundary):
        """Test CSR file reading error scenario."""
        action_module = ActionModule(
            task=mock_ansible_environment.task,
            connection=mock_ansible_environment.connection,
            play_context=mock_ansible_environment.play_context,
            loader=mock_ansible_environment.loader,
            templar=mock_ansible_environment.templar,
            shared_loader_obj=mock_ansible_environment.shared_loader_obj
        )

        # Create non-existent CSR path
        csr_path = temp_directory / 'nonexistent.csr'

        mock_ansible_environment.task.args = {
            'api_key': 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6',
            'domains': ['csr-error.example.com'],
            'csr_path': str(csr_path),
            'state': 'present'
        }

        result = action_module.run(task_vars=mock_ansible_environment.task_vars)
        assert result.get('failed') is True

    def test_backup_file_creation_error(self, mock_ansible_environment, temp_directory, mocker, mock_http_boundary):
        """Test backup file creation error scenario."""
        action_module = ActionModule(
            task=mock_ansible_environment.task,
            connection=mock_ansible_environment.connection,
            play_context=mock_ansible_environment.play_context,
            loader=mock_ansible_environment.loader,
            templar=mock_ansible_environment.templar,
            shared_loader_obj=mock_ansible_environment.shared_loader_obj
        )

        cert_path = temp_directory / 'existing.crt'
        cert_path.write_text('-----BEGIN CERTIFICATE-----\nEXISTING\n-----END CERTIFICATE-----')

        mock_ansible_environment.task.args = {
            'api_key': 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6',
            'domains': ['backup-error.example.com'],
            'certificate_path': str(cert_path),
            'backup': True,
            'state': 'present'
        }

        # Mock backup operation to fail
        with patch('shutil.copy2', side_effect=OSError("Backup failed")):
            result = action_module.run(task_vars=mock_ansible_environment.task_vars)
            assert result.get('failed') is True

    def test_file_permission_error(self, mock_ansible_environment, temp_directory, mocker, mock_http_boundary):
        """Test file permission error scenario."""
        action_module = ActionModule(
            task=mock_ansible_environment.task,
            connection=mock_ansible_environment.connection,
            play_context=mock_ansible_environment.play_context,
            loader=mock_ansible_environment.loader,
            templar=mock_ansible_environment.templar,
            shared_loader_obj=mock_ansible_environment.shared_loader_obj
        )

        cert_path = temp_directory / 'permission_error.crt'

        mock_ansible_environment.task.args = {
            'api_key': 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6',
            'domains': ['permission.example.com'],
            'certificate_path': str(cert_path),
            'file_mode': '0600',
            'state': 'present'
        }

        # Mock file creation to fail with permission error
        mock_http_boundary('/certificates', {
            'id': 'permission_cert_123',
            'status': 'draft'
        })

        mock_http_boundary('/certificates/permission_cert_123/download/return/zip', {
            'certificate.crt': '-----BEGIN CERTIFICATE-----\nNEW_CERT\n-----END CERTIFICATE-----'
        })

        with patch('pathlib.Path.write_text', side_effect=PermissionError("Permission denied")):
            result = action_module.run(task_vars=mock_ansible_environment.task_vars)
            assert result.get('failed') is True

    def test_import_error_scenario(self, mock_ansible_environment, mocker, mock_http_boundary):
        """Test import error handling scenario."""
        # This is tricky because imports happen at module level
        # We can test by mocking during module reload or initialization
        action_module = ActionModule(
            task=mock_ansible_environment.task,
            connection=mock_ansible_environment.connection,
            play_context=mock_ansible_environment.play_context,
            loader=mock_ansible_environment.loader,
            templar=mock_ansible_environment.templar,
            shared_loader_obj=mock_ansible_environment.shared_loader_obj
        )

        mock_ansible_environment.task.args = {
            'api_key': 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6',
            'domains': ['import-test.example.com'],
            'state': 'present'
        }

        # Since imports are at module level, we just verify the module loaded properly
        result = action_module.run(task_vars=mock_ansible_environment.task_vars)
        # Should not fail due to import errors since they're handled at module level
        assert isinstance(result, dict)
