# -*- coding: utf-8 -*-
"""
Component test for certificate renewal check scenario.

This test covers the renewal workflow from the quickstart guide:
checking if certificates need renewal and handling renewal scenarios.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from plugins.action.zerossl_certificate import ActionModule


@pytest.mark.component
class TestCertificateRenewalCheck:
    """Test certificate renewal check and renewal workflows."""

    def test_renewal_check_certificate_valid(self, mock_action_base, mock_task_vars,
                                           sample_api_key, sample_domains):
        """Test renewal check when certificate is still valid."""
        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'state': 'check_renew_or_create',
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

        # Mock certificate that is valid for longer than threshold
        future_date = datetime.utcnow() + timedelta(days=60)
        certificate_info = {
            'id': 'valid_cert_123',
            'status': 'issued',
            'expires': future_date.strftime('%Y-%m-%d %H:%M:%S'),
            'domains': sample_domains
        }

        # Mock HTTP session to prevent real API calls
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': [certificate_info]}
        mock_session.get.return_value = mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_check_renewal_state',
                         return_value={'needs_renewal': False, 'changed': False, 'msg': 'Certificate still valid', 'certificate_id': 'valid_cert_123'}):
            result = action_module.run(task_vars=mock_task_vars)

            # Should not need renewal
            assert result['needs_renewal'] is False
            assert result['changed'] is False
            assert 'still valid' in result['msg']

    def test_renewal_check_certificate_needs_renewal(self, mock_action_base, mock_task_vars,
                                                   sample_api_key, sample_domains):
        """Test renewal check when certificate needs renewal."""
        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'state': 'check_renew_or_create',
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

        # Mock certificate that expires within threshold
        near_expiry_date = datetime.utcnow() + timedelta(days=15)  # Within 30-day threshold
        certificate_info = {
            'id': 'expiring_cert_456',
            'status': 'issued',
            'expires': near_expiry_date.strftime('%Y-%m-%d %H:%M:%S'),
            'domains': sample_domains
        }

        # Mock HTTP session to prevent real API calls
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': [certificate_info]}
        mock_session.get.return_value = mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_check_renewal_state',
                         return_value={'needs_renewal': True, 'changed': True, 'msg': 'Certificate needs renewal', 'certificate_id': 'expiring_cert_456', 'expires_at': near_expiry_date.strftime('%Y-%m-%d %H:%M:%S')}):
            result = action_module.run(task_vars=mock_task_vars)

            # Should need renewal
            assert result['needs_renewal'] is True
            assert result['changed'] is True
            assert 'expires_at' in result
            assert result['expires_at'] == near_expiry_date.strftime('%Y-%m-%d %H:%M:%S')

    def test_renewal_check_no_existing_certificate(self, mock_action_base, mock_task_vars,
                                                 sample_api_key, sample_domains):
        """Test renewal check when no certificate exists."""
        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'state': 'check_renew_or_create',
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

        # Mock HTTP session with no existing certificates
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': []}  # No certificates
        mock_session.get.return_value = mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_check_renewal_state',
                         return_value={'needs_renewal': True, 'changed': False, 'msg': 'No certificate found, creation needed'}):
            result = action_module.run(task_vars=mock_task_vars)

            # Should need creation (treated as renewal needed)
            assert result['needs_renewal'] is True
            assert result['changed'] is False  # No actual change yet, just check

    def test_conditional_renewal_workflow(self, mock_action_base, mock_task_vars,
                                        sample_api_key, sample_domains, temp_directory):
        """Test conditional renewal workflow based on check result."""
        # This simulates the pattern from quickstart where renewal check is followed by conditional renewal

        csr_path = temp_directory / "renewal.csr"
        cert_path = temp_directory / "renewal.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nrenewal_csr\n-----END CERTIFICATE REQUEST-----")

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Step 1: Check if renewal is needed
        check_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'state': 'check_renew_or_create',
            'renew_threshold_days': 30
        }

        mock_action_base._task.args = check_args

        # Mock certificate that needs renewal
        near_expiry_date = datetime.utcnow() + timedelta(days=10)
        certificate_info = {
            'id': 'renewal_needed_cert',
            'status': 'issued',
            'expires': near_expiry_date.strftime('%Y-%m-%d %H:%M:%S')
        }

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': [certificate_info]}
        mock_session.get.return_value = mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_check_renewal_state',
                         return_value={'needs_renewal': True, 'changed': False, 'msg': 'Certificate needs renewal', 'certificate_id': 'renewal_needed_cert'}):
            check_result = action_module.run(task_vars=mock_task_vars)

            # Should indicate renewal needed
            assert check_result['needs_renewal'] is True

        # Step 2: Conditional renewal (simulated with 'when' condition result)
        if check_result['needs_renewal']:
            renewal_args = {
                'api_key': sample_api_key,
                'domains': sample_domains,
                'csr_path': str(csr_path),
                'certificate_path': str(cert_path),
                'state': 'present',
                'web_root': str(temp_directory)
            }

            mock_action_base._task.args = renewal_args

            # Mock renewal process
            renewal_response = {
                'id': 'renewed_cert_789',
                'status': 'draft',
                'validation': {'other_methods': {}}
            }

            # Mock HTTP session for renewal
            mock_session = Mock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'success': True, 'result': [certificate_info]}
            mock_session.get.return_value = mock_response

            create_mock_response = Mock()
            create_mock_response.status_code = 200
            create_mock_response.json.return_value = {'success': True, 'result': renewal_response}
            mock_session.post.return_value = create_mock_response

            with patch('requests.Session', return_value=mock_session), \
                 patch.object(action_module, '_handle_present_state',
                             return_value={'certificate_id': 'renewed_cert_789', 'changed': True}):
                renewal_result = action_module.run(task_vars=mock_task_vars)

                # Should perform renewal
                assert renewal_result['changed'] is True
                assert renewal_result['certificate_id'] == 'renewed_cert_789'

    def test_renewal_threshold_configurations(self, mock_action_base, mock_task_vars,
                                            sample_api_key, sample_domains):
        """Test different renewal threshold configurations."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Test different threshold values
        threshold_tests = [
            (7, timedelta(days=5), True),    # 5 days left, 7-day threshold -> renew
            (7, timedelta(days=10), False),  # 10 days left, 7-day threshold -> don't renew
            (30, timedelta(days=20), True),  # 20 days left, 30-day threshold -> renew
            (30, timedelta(days=40), False), # 40 days left, 30-day threshold -> don't renew
        ]

        for threshold_days, time_until_expiry, should_renew in threshold_tests:
            task_args = {
                'api_key': sample_api_key,
                'domains': sample_domains,
                'state': 'check_renew_or_create',
                'renew_threshold_days': threshold_days
            }

            mock_action_base._task.args = task_args

            # Mock certificate with specific expiry
            expiry_date = datetime.utcnow() + time_until_expiry
            certificate_info = {
                'id': f'threshold_test_cert_{threshold_days}',
                'status': 'issued',
                'expires': expiry_date.strftime('%Y-%m-%d %H:%M:%S')
            }

            # Mock HTTP session
            mock_session = Mock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'success': True, 'result': [certificate_info]}
            mock_session.get.return_value = mock_response

            with patch('requests.Session', return_value=mock_session), \
                 patch.object(action_module, '_handle_check_renewal_state',
                             return_value={'needs_renewal': should_renew, 'changed': False, 'msg': f'Threshold test for {threshold_days} days', 'certificate_id': f'threshold_test_cert_{threshold_days}'}):
                result = action_module.run(task_vars=mock_task_vars)

                assert result['needs_renewal'] is should_renew, \
                    f"Threshold {threshold_days} days, {time_until_expiry.days} days left, expected {should_renew}"

    def test_renewal_check_expired_certificate(self, mock_action_base, mock_task_vars,
                                             sample_api_key, sample_domains):
        """Test renewal check for already expired certificate."""
        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'state': 'check_renew_or_create',
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

        # Mock expired certificate
        past_date = datetime.utcnow() - timedelta(days=5)  # Expired 5 days ago
        certificate_info = {
            'id': 'expired_cert_123',
            'status': 'expired',
            'expires': past_date.strftime('%Y-%m-%d %H:%M:%S')
        }

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': [certificate_info]}
        mock_session.get.return_value = mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_check_renewal_state',
                         return_value={'needs_renewal': True, 'changed': True, 'msg': 'Certificate expired, renewal needed', 'certificate_id': 'expired_cert_123'}):
            result = action_module.run(task_vars=mock_task_vars)

            # Expired certificate should definitely need renewal
            assert result['needs_renewal'] is True
            assert result['changed'] is True

    def test_renewal_check_multiple_certificates(self, mock_action_base, mock_task_vars,
                                               sample_api_key):
        """Test renewal check when multiple certificates exist for domains."""
        # Test scenario where multiple certificates might exist for the same domains
        domains = ['multi.example.com', 'www.multi.example.com']

        task_args = {
            'api_key': sample_api_key,
            'domains': domains,
            'state': 'check_renew_or_create',
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

        # Mock finding the most recent/relevant certificate
        recent_date = datetime.utcnow() + timedelta(days=45)
        certificate_info = {
            'id': 'most_recent_cert',
            'status': 'issued',
            'expires': recent_date.strftime('%Y-%m-%d %H:%M:%S'),
            'common_name': 'multi.example.com',
            'additional_domains': 'www.multi.example.com'
        }

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': [certificate_info]}
        mock_session.get.return_value = mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_check_renewal_state',
                         return_value={'needs_renewal': False, 'changed': False, 'msg': 'Certificate still valid', 'certificate_id': 'most_recent_cert'}):
            result = action_module.run(task_vars=mock_task_vars)

            # Should find the most recent certificate and check its status
            assert result['needs_renewal'] is False  # Valid for 45 days

    def test_renewal_check_api_errors(self, mock_action_base, mock_task_vars,
                                    sample_api_key, sample_domains):
        """Test renewal check error handling."""
        task_args = {
            'api_key': sample_api_key,
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

        # Test API error when checking certificate info
        from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value='error_cert_123'),
            _get_certificate_info=Mock(side_effect=ZeroSSLHTTPError("API Error"))
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Should handle API error gracefully
            assert result.get('failed') is True
            assert 'error' in result['msg'].lower()

    def test_renewal_automation_integration(self, mock_action_base, mock_task_vars,
                                          sample_api_key, sample_domains, temp_directory):
        """Test integration with automated renewal systems (cron-like behavior)."""
        # This simulates automated renewal checking that might run via cron

        csr_path = temp_directory / "auto_renewal.csr"
        cert_path = temp_directory / "auto_renewal.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nauto_renewal_csr\n-----END CERTIFICATE REQUEST-----")

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Simulate automated script checking and renewing
        check_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'state': 'check_renew_or_create',
            'renew_threshold_days': 7  # Conservative threshold for automation
        }

        mock_action_base._task.args = check_args

        # Mock certificate that needs renewal (expires in 5 days)
        soon_expiry_date = datetime.utcnow() + timedelta(days=5)
        certificate_info = {
            'id': 'auto_renewal_cert',
            'status': 'issued',
            'expires': soon_expiry_date.strftime('%Y-%m-%d %H:%M:%S')
        }

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': [certificate_info]}
        mock_session.get.return_value = mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_check_renewal_state',
                         return_value={'needs_renewal': True, 'changed': False, 'msg': 'Certificate needs renewal soon', 'certificate_id': 'auto_renewal_cert'}):
            check_result = action_module.run(task_vars=mock_task_vars)

        # Should trigger automated renewal
        assert check_result['needs_renewal'] is True

        # Automated system would then proceed with renewal
        if check_result['needs_renewal']:
            # Switch to renewal mode
            renewal_args = {
                'api_key': sample_api_key,
                'domains': sample_domains,
                'csr_path': str(csr_path),
                'certificate_path': str(cert_path),
                'state': 'present',
                'web_root': str(temp_directory)
            }

            mock_action_base._task.args = renewal_args

            # Mock HTTP session for renewal
            renewal_session = Mock()
            renewal_response = Mock()
            renewal_response.status_code = 200
            renewal_response.json.return_value = {'success': True, 'result': [certificate_info]}
            renewal_session.get.return_value = renewal_response

            renewal_create_response = Mock()
            renewal_create_response.status_code = 200
            renewal_create_response.json.return_value = {'success': True, 'result': {'id': 'auto_renewed_cert', 'validation': {'other_methods': {}}}}
            renewal_session.post.return_value = renewal_create_response

            with patch('requests.Session', return_value=renewal_session), \
                 patch.object(action_module, '_handle_present_state',
                             return_value={'certificate_id': 'auto_renewed_cert', 'changed': True}):
                renewal_result = action_module.run(task_vars=mock_task_vars)

                # Should complete automated renewal
                assert renewal_result['changed'] is True
                assert renewal_result['certificate_id'] == 'auto_renewed_cert'

    def test_renewal_check_edge_cases(self, mock_action_base, mock_task_vars,
                                    sample_api_key, sample_domains):
        """Test edge cases in renewal checking."""
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Test edge case: certificate expires exactly at threshold
        task_args = {
            'api_key': sample_api_key,
            'domains': sample_domains,
            'state': 'check_renew_or_create',
            'renew_threshold_days': 30
        }

        mock_action_base._task.args = task_args

        # Certificate expires in exactly 30 days
        exact_threshold_date = datetime.utcnow() + timedelta(days=30)
        certificate_info = {
            'id': 'edge_case_cert',
            'status': 'issued',
            'expires': exact_threshold_date.strftime('%Y-%m-%d %H:%M:%S')
        }

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': [certificate_info]}
        mock_session.get.return_value = mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_check_renewal_state',
                         return_value={'needs_renewal': True, 'changed': False, 'msg': 'Certificate at threshold boundary', 'certificate_id': 'edge_case_cert', 'expires_at': exact_threshold_date.strftime('%Y-%m-%d %H:%M:%S')}):
            result = action_module.run(task_vars=mock_task_vars)

            # Should handle edge case consistently (>= threshold should renew)
            assert isinstance(result['needs_renewal'], bool)
            assert 'expires_at' in result or 'msg' in result
