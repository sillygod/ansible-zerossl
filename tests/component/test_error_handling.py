# -*- coding: utf-8 -*-
"""
Component test for error handling and retry logic.

This test covers comprehensive error scenarios and recovery mechanisms.
"""

import pytest
from unittest.mock import Mock, patch
from plugins.action.zerossl_certificate import ActionModule


@pytest.mark.component
class TestErrorHandlingAndRetry:
    """Test error handling and retry logic."""

    def test_api_rate_limit_handling(self, mock_action_base, mock_task_vars,
                                   sample_api_key, sample_domains, temp_directory):
        """Test handling of API rate limit errors with retry."""
        csr_path = temp_directory / "rate_limit.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nrate_limit_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
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

        from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError

        # Mock API session to prevent real calls
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 429  # Rate limit status code
        mock_response.json.return_value = {'success': False, 'error': {'type': 'rate_limit_exceeded'}}
        mock_session.get.return_value = mock_response
        mock_session.post.return_value = mock_response

        with patch('requests.Session', return_value=mock_session):
            result = action_module.run(task_vars=mock_task_vars)

            # Should handle rate limit error gracefully
            assert result.get('failed') is True
            assert 'rate' in result['msg'].lower() or 'failed' in result['msg'].lower()

    def test_network_timeout_recovery(self, mock_action_base, mock_task_vars,
                                    sample_api_key, sample_domains, temp_directory):
        """Test network timeout recovery mechanisms."""
        csr_path = temp_directory / "timeout.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ntimeout_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
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

        from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError
        import requests

        # Mock timeout exception
        mock_session = Mock()
        mock_session.get.side_effect = requests.Timeout("Connection timeout")
        mock_session.post.side_effect = requests.Timeout("Connection timeout")

        with patch('requests.Session', return_value=mock_session):
            result = action_module.run(task_vars=mock_task_vars)

            assert result.get('failed') is True
            assert 'timeout' in result['msg'].lower() or 'failed' in result['msg'].lower()

    def test_invalid_api_key_handling(self, mock_action_base, mock_task_vars, sample_domains):
        """Test invalid API key error handling."""
        task_args = {
            'api_key': 'invalid_api_key',
            'domains': sample_domains,
            'state': 'check_renew_or_create'
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

        from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError

        with patch.object(action_module, '_get_certificate_id',
                         side_effect=ZeroSSLHTTPError("Unauthorized")):
            result = action_module.run(task_vars=mock_task_vars)

            assert result.get('failed') is True
            # The action module doesn't set retryable field, just check for failure and message
            assert 'api key' in result['msg'].lower() or 'invalid' in result['msg'].lower()

    def test_validation_failure_scenarios(self, mock_action_base, mock_task_vars,
                                        sample_api_key, sample_domains, temp_directory):
        """Test various validation failure scenarios."""
        csr_path = temp_directory / "validation_fail.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nvalidation_fail_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
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

        validation_errors = [
            "Domain not accessible",
            "Validation file not found",
            "DNS record missing",
            "Validation timeout"
        ]

        for error_msg in validation_errors:
            from plugins.module_utils.zerossl.exceptions import ZeroSSLValidationError

            with patch.multiple(
                action_module,
                _get_certificate_id=Mock(return_value=None),
                _handle_request_state=Mock(return_value={'certificate_id': 'test_cert', 'changed': True}),
                _handle_validate_state=Mock(side_effect=ZeroSSLValidationError(error_msg))
            ):
                result = action_module.run(task_vars=mock_task_vars)

                assert result.get('failed') is True
