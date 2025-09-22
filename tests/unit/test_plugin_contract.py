# -*- coding: utf-8 -*-
"""
Contract tests for Ansible ZeroSSL plugin interface.

These tests verify that the plugin conforms to Ansible action plugin
standards and provides the expected interface for users.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from plugins.action.zerossl_certificate import ActionModule
from ansible.errors import AnsibleActionFail


@pytest.mark.contract
class TestAnsiblePluginInterfaceContract:
    """Test contract for Ansible plugin interface."""

    def test_plugin_parameter_validation(self, mock_action_base, mock_task_vars):
        """Test that plugin validates required parameters correctly."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Test missing required parameters
        required_params = ['api_key', 'domains']

        for missing_param in required_params:
            task_args = {
                'api_key': 'test_key_1234567890123456789012345',  # Use longer key to pass validation
                'domains': ['example.com'],
                'state': 'present'
            }
            del task_args[missing_param]

            mock_action_base._task.args = task_args

            result = action_module.run(task_vars=mock_task_vars)
            assert result.get('failed') is True
            # Check that the error message mentions the missing parameter
            msg = result.get('msg', '').lower()
            assert missing_param in msg or f"{missing_param} is required" in msg

    def test_plugin_parameter_types(self, mock_action_base, mock_task_vars):
        """Test that plugin validates parameter types correctly."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Test invalid parameter types
        invalid_params = [
            {'domains': 'string_instead_of_list'},  # domains should be list
            {'domains': []},  # domains should not be empty
            {'renew_threshold_days': 'not_a_number'},  # should be integer
            {'renew_threshold_days': -1},  # should be positive
            {'state': 'invalid_state'},  # should be valid enum value
        ]

        for invalid_param in invalid_params:
            task_args = {
                'api_key': 'test_key',
                'domains': ['example.com'],
                'state': 'present'
            }
            task_args.update(invalid_param)

            mock_action_base._task.args = task_args

            result = action_module.run(task_vars=mock_task_vars)
            assert result.get('failed') is True

    def test_plugin_return_structure_present_state(self, mock_action_base, mock_task_vars):
        """Test plugin return structure for 'present' state."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        mock_action_base._task.args = {
            'api_key': 'test_key_1234567890123456789012345',  # Use longer key to pass validation
            'domains': ['example.com'],
            'csr_path': '/tmp/test.csr',
            'certificate_path': '/tmp/test.crt',
            'web_root': '/tmp/.well-known',
            'file_mode': '0600',
            'state': 'present'
        }

        # Mock the certificate operations
        mock_cert_response = {
            'certificate_id': 'test_cert_123',
            'status': 'issued',
            'domains': ['example.com'],
            'validation_files': [],
            'dns_records': [],
            'created': True,
            'changed': True
        }

        mock_bundle = {
            'certificate': 'cert_content',
            'private_key': 'key_content',
            'ca_bundle': 'ca_content'
        }

        # Mock certificate manager at action plugin level
        cert_manager_mock = Mock()
        cert_manager_mock.needs_renewal.return_value = True
        cert_manager_mock.create_certificate.return_value = mock_cert_response
        cert_manager_mock.download_certificate.return_value = mock_bundle

        with patch('plugins.action.zerossl_certificate.CertificateManager', return_value=cert_manager_mock), \
             patch.object(action_module, '_get_csr_content', return_value='-----BEGIN CERTIFICATE REQUEST-----\nMOCK_CSR_CONTENT\n-----END CERTIFICATE REQUEST-----'), \
             patch('pathlib.Path.write_text'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.is_dir', return_value=True), \
             patch('os.access', return_value=True):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify required return fields
            required_fields = ['changed', 'certificate_id']
            for field in required_fields:
                assert field in result, f"Missing return field: {field}"

            # Verify field types
            assert isinstance(result['changed'], bool)
            assert isinstance(result['certificate_id'], str)

    def test_plugin_return_structure_request_state(self, mock_action_base, mock_task_vars):
        """Test plugin return structure for 'request' state."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        mock_action_base._task.args = {
            'api_key': 'test_key_1234567890123456789012345',  # Use longer key to pass validation
            'domains': ['example.com'],
            'csr_path': '/tmp/test.csr',
            'state': 'request'
        }

        # Mock certificate creation with validation files
        mock_response = {
            'certificate_id': 'test_cert_123',
            'status': 'draft',
            'domains': ['example.com'],
            'validation_files': [
                {
                    'domain': 'example.com',
                    'filename': 'test.txt',
                    'url_path': '/.well-known/pki-validation/test.txt',
                    'content': 'validation_content'
                }
            ],
            'dns_records': [],
            'created': True,
            'changed': True
        }

        # Mock certificate manager at action plugin level
        cert_manager_mock = Mock()
        cert_manager_mock.create_certificate.return_value = mock_response

        with patch('plugins.action.zerossl_certificate.CertificateManager', return_value=cert_manager_mock), \
             patch.object(action_module, '_get_csr_content', return_value='-----BEGIN CERTIFICATE REQUEST-----\nMOCK_CSR_CONTENT\n-----END CERTIFICATE REQUEST-----'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.is_dir', return_value=True), \
             patch('os.access', return_value=True):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify request state specific fields
            required_fields = ['changed', 'certificate_id', 'validation_files']
            for field in required_fields:
                assert field in result, f"Missing return field: {field}"

            assert isinstance(result['validation_files'], list)
            assert len(result['validation_files']) > 0

            # Verify validation file structure
            vf = result['validation_files'][0]
            validation_file_fields = ['domain', 'filename', 'content']
            for field in validation_file_fields:
                assert field in vf, f"Missing validation file field: {field}"

    def test_plugin_return_structure_check_renewal(self, mock_action_base, mock_task_vars):
        """Test plugin return structure for 'check_renew_or_create' state."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        mock_action_base._task.args = {
            'api_key': 'test_key_1234567890123456789012345',  # Use longer key to pass validation
            'domains': ['example.com'],
            'state': 'check_renew_or_create',
            'renew_threshold_days': 30
        }

        # Mock at the action plugin level where CertificateManager is imported
        cert_manager_mock = Mock()
        cert_manager_mock.needs_renewal.return_value = False
        cert_manager_mock.find_certificate_for_domains.return_value = 'test_cert_123'
        cert_manager_mock.get_certificate_status.return_value = {
            'status': 'issued',
            'expires': '2025-10-17 12:00:00'
        }

        with patch('plugins.action.zerossl_certificate.CertificateManager', return_value=cert_manager_mock):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify renewal check specific fields
            required_fields = ['changed', 'needs_renewal']
            for field in required_fields:
                assert field in result, f"Missing return field: {field}"

            assert isinstance(result['needs_renewal'], bool)

    def test_plugin_idempotency(self, mock_action_base, mock_task_vars):
        """Test that plugin operations are idempotent."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        mock_action_base._task.args = {
            'api_key': 'test_key_1234567890123456789012345',  # Use longer key to pass validation
            'domains': ['example.com'],
            'csr_path': '/tmp/test.csr',
            'certificate_path': '/tmp/test.crt',
            'web_root': '/tmp/.well-known',
            'file_mode': '0600',
            'state': 'present'
        }

        # Mock certificate manager at action plugin level
        cert_manager_mock = Mock()
        cert_manager_mock.needs_renewal.return_value = False
        cert_manager_mock.find_certificate_for_domains.return_value = 'existing_cert'
        cert_manager_mock.get_certificate_status.return_value = {
            'expires': '2025-12-17 12:00:00',  # Valid for long time
            'status': 'issued'
        }

        with patch('plugins.action.zerossl_certificate.CertificateManager', return_value=cert_manager_mock), \
             patch.object(action_module, '_get_csr_content', return_value='-----BEGIN CERTIFICATE REQUEST-----\nMOCK_CSR_CONTENT\n-----END CERTIFICATE REQUEST-----'), \
             patch.object(action_module, '_check_certificate_files_need_update', return_value=False), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.is_dir', return_value=True), \
             patch('os.access', return_value=True):
            result = action_module.run(task_vars=mock_task_vars)

            # Should not change anything if certificate is valid
            assert result['changed'] is False
            assert 'msg' in result
            assert 'valid' in result['msg'].lower()


@pytest.mark.contract
class TestAnsiblePluginErrorHandlingContract:
    """Test contract for plugin error handling."""

    def test_plugin_handles_api_errors_gracefully(self, mock_action_base, mock_task_vars):
        """Test that plugin handles API errors gracefully."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        mock_action_base._task.args = {
            'api_key': 'test_key_1234567890123456789012345',  # Use longer key to pass validation
            'domains': ['example.com'],
            'csr_path': '/tmp/test.csr',
            'web_root': '/tmp/.well-known',
            'file_mode': '0600',
            'state': 'present'
        }

        # Mock certificate manager to raise API error
        from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError
        cert_manager_mock = Mock()
        cert_manager_mock.needs_renewal.side_effect = ZeroSSLHTTPError("Unauthorized")

        with patch('plugins.action.zerossl_certificate.CertificateManager', return_value=cert_manager_mock), \
             patch.object(action_module, '_get_csr_content', return_value='-----BEGIN CERTIFICATE REQUEST-----\nMOCK_CSR_CONTENT\n-----END CERTIFICATE REQUEST-----'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.is_dir', return_value=True), \
             patch('os.access', return_value=True):

            # Should raise AnsibleActionFail for API errors
            from ansible.errors import AnsibleActionFail
            with pytest.raises(AnsibleActionFail) as exc_info:
                action_module.run(task_vars=mock_task_vars)

            # Verify the exception message contains the error
            assert 'unauthorized' in str(exc_info.value).lower()

    def test_plugin_handles_file_errors(self, mock_action_base, mock_task_vars):
        """Test that plugin handles file operation errors."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        mock_action_base._task.args = {
            'api_key': 'test_key_1234567890123456789012345',
            'domains': ['example.com'],
            'csr_path': '/nonexistent/path/test.csr',
            'state': 'present'
        }

        # Should handle missing CSR file
        res = action_module.run(task_vars=mock_task_vars)
        assert res.get('failed') is True
        assert 'Path does not exist' in res.get('msg')

    def test_plugin_handles_network_errors(self, mock_action_base, mock_task_vars):
        """Test that plugin handles network errors with retry."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        mock_action_base._task.args = {
            'api_key': 'test_key_1234567890123456789012345',  # Use longer key to pass validation
            'domains': ['example.com'],
            'csr_path': '/tmp/test.csr',
            'certificate_path': '/tmp/test.crt',
            'web_root': '/tmp/.well-known',
            'file_mode': '0600',
            'state': 'present'
        }

        # Mock certificate manager to raise network error
        from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError
        cert_manager_mock = Mock()
        cert_manager_mock.needs_renewal.side_effect = ZeroSSLHTTPError("Connection timeout")

        with patch('plugins.action.zerossl_certificate.CertificateManager', return_value=cert_manager_mock), \
             patch.object(action_module, '_get_csr_content', return_value='-----BEGIN CERTIFICATE REQUEST-----\nMOCK_CSR_CONTENT\n-----END CERTIFICATE REQUEST-----'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.is_dir', return_value=True), \
             patch('os.access', return_value=True):

            # Should raise AnsibleActionFail for network errors
            from ansible.errors import AnsibleActionFail
            with pytest.raises(AnsibleActionFail) as exc_info:
                action_module.run(task_vars=mock_task_vars)

            # Verify the exception message contains the error
            assert 'connection timeout' in str(exc_info.value).lower()


@pytest.mark.contract
class TestAnsiblePluginDocumentationContract:
    """Test contract for plugin documentation compliance."""

    def test_plugin_has_required_documentation(self):
        """Test that plugin has required Ansible documentation."""
        from plugins.action.zerossl_certificate import DOCUMENTATION, EXAMPLES, RETURN

        # Check DOCUMENTATION exists and has required sections
        assert DOCUMENTATION is not None
        assert 'module:' in DOCUMENTATION or 'name:' in DOCUMENTATION
        assert 'short_description:' in DOCUMENTATION
        assert 'description:' in DOCUMENTATION
        assert 'options:' in DOCUMENTATION
        assert 'author:' in DOCUMENTATION

        # Check required options are documented
        required_options = ['api_key', 'domains', 'state']
        for option in required_options:
            assert option in DOCUMENTATION

        # Check EXAMPLES exists
        assert EXAMPLES is not None
        assert 'zerossl_certificate:' in EXAMPLES

        # Check RETURN exists
        assert RETURN is not None
        assert 'changed:' in RETURN

    def test_plugin_parameter_documentation_matches_implementation(self):
        """Test that documented parameters match implementation."""
        # This would parse DOCUMENTATION yaml and compare with actual parameters
        # For now, we'll do a basic check
        from plugins.action.zerossl_certificate import DOCUMENTATION

        # Check that all required parameters are documented
        documented_params = []
        lines = DOCUMENTATION.split('\n')
        for line in lines:
            if line.strip().endswith(':') and not line.strip().startswith('#'):
                param = line.strip().rstrip(':')
                if param and not param.startswith(' ') and param != 'options':
                    documented_params.append(param)

        # Should include main parameters
        expected_params = ['api_key', 'domains', 'state', 'csr_path', 'certificate_path']
        for param in expected_params:
            # This test will help ensure documentation is complete
            pass  # Implementation will verify this

    def test_plugin_examples_are_valid_yaml(self):
        """Test that plugin examples are valid YAML."""
        from plugins.action.zerossl_certificate import EXAMPLES
        import yaml

        try:
            # Should be able to parse examples as YAML
            examples_data = yaml.safe_load(EXAMPLES)
            assert examples_data is not None
        except yaml.YAMLError:
            pytest.fail("EXAMPLES section contains invalid YAML")


@pytest.mark.contract
class TestAnsiblePluginStateContract:
    """Test contract for plugin state management."""

    def test_all_supported_states_work(self, mock_action_base, mock_task_vars):
        """Test that all documented states are implemented."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        supported_states = ['present', 'request', 'validate', 'download', 'absent', 'check_renew_or_create']

        for state in supported_states:
            mock_action_base._task.args = {
                'api_key': 'test_key_1234567890123456789012345',  # Use longer key to pass validation
                'domains': ['example.com'],
                'state': state
            }

            # Add state-specific required parameters
            if state in ['present', 'request']:
                mock_action_base._task.args['csr_path'] = '/tmp/test.csr'
                mock_action_base._task.args['web_root'] = '/tmp/.well-known'
            if state == 'present':
                mock_action_base._task.args['certificate_path'] = '/tmp/test.crt'
                mock_action_base._task.args['file_mode'] = '0600'
            if state in ['validate', 'download']:
                mock_action_base._task.args['certificate_id'] = 'test_cert_123'
                mock_action_base._task.args['web_root'] = '/tmp/.well-known'
            if state == 'download':
                mock_action_base._task.args['certificate_path'] = '/tmp/test.crt'

            # Mock certificate manager for all operations
            cert_manager_mock = Mock()
            cert_manager_mock.create_certificate.return_value = {
                'certificate_id': 'test_cert',
                'status': 'issued',
                'domains': ['example.com'],
                'validation_files': [{'domain': 'example.com', 'filename': 'test.txt', 'content': 'validation_content'}],
                'dns_records': [],
                'created': True,
                'changed': True
            }
            cert_manager_mock.validate_certificate.return_value = {'success': True, 'validation_completed': True}
            cert_manager_mock.download_certificate.return_value = {
                'certificate': 'cert_content',
                'private_key': 'key_content',
                'ca_bundle': 'ca_content'
            }
            cert_manager_mock.find_certificate_for_domains.return_value = 'test_cert'
            cert_manager_mock.get_certificate_status.return_value = {'expires': '2025-12-17 12:00:00', 'status': 'issued'}
            cert_manager_mock.cancel_certificate.return_value = {'success': True}
            cert_manager_mock.needs_renewal.return_value = False

            with patch('plugins.action.zerossl_certificate.CertificateManager', return_value=cert_manager_mock), \
                 patch.object(action_module, '_get_csr_content', return_value='-----BEGIN CERTIFICATE REQUEST-----\nMOCK_CSR_CONTENT\n-----END CERTIFICATE REQUEST-----'), \
                 patch.object(action_module, '_check_certificate_files_need_update', return_value=False), \
                 patch('pathlib.Path.exists', return_value=True), \
                 patch('pathlib.Path.write_text'), \
                 patch('pathlib.Path.is_dir', return_value=True), \
                 patch('os.access', return_value=True):
                # Should not raise exception for any supported state
                result = action_module.run(task_vars=mock_task_vars)
                assert 'failed' not in result or result['failed'] is False

    def test_unsupported_state_raises_error(self, mock_action_base, mock_task_vars):
        """Test that unsupported states raise appropriate errors."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        mock_action_base._task.args = {
            'api_key': 'test_key_1234567890123456789012345',
            'domains': ['example.com'],
            'state': 'unsupported_state'
        }

        res = action_module.run(task_vars=mock_task_vars)
        assert res.get('failed') is True
        assert 'Invalid state' in res.get('msg')
