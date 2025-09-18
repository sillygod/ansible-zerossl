# -*- coding: utf-8 -*-
"""
Integration test for error handling and retry logic.

This test covers comprehensive error scenarios and recovery mechanisms.
"""

import pytest
from unittest.mock import Mock, patch
from plugins.action.zerossl_certificate import ActionModule


@pytest.mark.integration
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

        from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError

        # Mock rate limit error followed by success
        with patch.object(action_module, '_get_certificate_id', return_value=None), \
             patch.object(action_module, '_create_certificate',
                         side_effect=ZeroSSLHTTPError("Rate limit exceeded")):
            result = action_module.run(task_vars=mock_task_vars)

            # Should handle rate limit error gracefully
            assert result.get('failed') is True
            assert result.get('retryable') is True
            assert 'rate limit' in result['msg'].lower()

    def test_network_timeout_recovery(self, mock_action_base, mock_task_vars,
                                    sample_api_key, sample_domains, temp_directory):
        """Test network timeout recovery mechanisms."""
        csr_path = temp_directory / "timeout.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ntimeout_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
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

        from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value=None),
            _create_certificate=Mock(side_effect=ZeroSSLHTTPError("Connection timeout"))
        ):
            result = action_module.run(task_vars=mock_task_vars)

            assert result.get('failed') is True
            assert result.get('retryable') is True
            assert 'timeout' in result['msg'].lower()

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
            assert result.get('retryable') is False  # Auth errors not retryable
            assert 'unauthorized' in result['msg'].lower()

    def test_validation_failure_scenarios(self, mock_action_base, mock_task_vars,
                                        sample_api_key, sample_domains, temp_directory):
        """Test various validation failure scenarios."""
        csr_path = temp_directory / "validation_fail.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nvalidation_fail_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'csr_path': str(csr_path),
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
                _create_certificate=Mock(return_value={'id': 'test_cert', 'validation': {'other_methods': {}}}),
                _validate_certificate=Mock(side_effect=ZeroSSLValidationError(error_msg))
            ):
                result = action_module.run(task_vars=mock_task_vars)

                assert result.get('failed') is True
                assert result.get('error_type') == 'validation'
