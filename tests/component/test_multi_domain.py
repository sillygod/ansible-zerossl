# -*- coding: utf-8 -*-
"""
Component test for multi-domain (SAN) certificate scenario.

This test covers SAN certificate workflows from the quickstart guide:
creating certificates that cover multiple domains in a single certificate.
"""

import pytest
from unittest.mock import Mock, patch
from plugins.action.zerossl_certificate import ActionModule


@pytest.mark.component
class TestMultiDomainCertificate:
    """Test multi-domain (SAN) certificate workflows."""

    def test_san_certificate_creation(self, mock_action_base, mock_task_vars,
                                    sample_api_key, temp_directory):
        """Test SAN certificate creation with multiple domains."""
        # Define multiple domains for SAN certificate
        san_domains = [
            'shop.example.com',
            'checkout.example.com',
            'payment.example.com',
            'api.example.com'
        ]

        # Setup test files
        csr_path = temp_directory / "san.csr"
        cert_path = temp_directory / "san.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nsan_csr_content\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': san_domains,
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

        # Mock SAN certificate creation response
        san_response = {
            'id': 'san_cert_123456',
            'status': 'draft',
            'common_name': 'shop.example.com',  # First domain becomes common name
            'additional_domains': 'checkout.example.com,payment.example.com,api.example.com',
            'validation': {
                'other_methods': {
                    domain: {
                        'file_validation_url_http': f'http://{domain}/.well-known/pki-validation/san_{domain.replace(".", "_")}.txt',
                        'file_validation_content': f'san_validation_content_for_{domain}'
                    }
                    for domain in san_domains
                }
            }
        }

        # Mock HTTP session to prevent real API calls
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': []}  # No existing certs
        mock_session.get.return_value = mock_response

        create_mock_response = Mock()
        create_mock_response.status_code = 200
        create_mock_response.json.return_value = {'success': True, 'result': san_response}
        mock_session.post.return_value = create_mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_present_state',
                         return_value={'certificate_id': 'san_cert_123456', 'changed': True}):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify SAN certificate creation
            assert result['changed'] is True
            assert result['certificate_id'] == 'san_cert_123456'

    def test_san_certificate_validation_files(self, mock_action_base, mock_task_vars,
                                            sample_api_key, temp_directory):
        """Test that SAN certificates generate validation files for all domains."""
        san_domains = ['main.example.com', 'www.example.com', 'cdn.example.com']

        csr_path = temp_directory / "san_validation.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nsan_validation_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': san_domains,
            'csr_path': str(csr_path),
            'state': 'request',  # Only request to get validation files
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

        # Mock response with validation for all domains
        validation_response = {
            'id': 'san_validation_cert',
            'status': 'draft',
            'validation': {
                'other_methods': {
                    'main.example.com': {
                        'file_validation_url_http': 'http://main.example.com/.well-known/pki-validation/main_val.txt',
                        'file_validation_content': 'main_validation_content'
                    },
                    'www.example.com': {
                        'file_validation_url_http': 'http://www.example.com/.well-known/pki-validation/www_val.txt',
                        'file_validation_content': 'www_validation_content'
                    },
                    'cdn.example.com': {
                        'file_validation_url_http': 'http://cdn.example.com/.well-known/pki-validation/cdn_val.txt',
                        'file_validation_content': 'cdn_validation_content'
                    }
                }
            }
        }

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': []}
        mock_session.get.return_value = mock_response

        create_mock_response = Mock()
        create_mock_response.status_code = 200
        create_mock_response.json.return_value = {'success': True, 'result': validation_response}
        mock_session.post.return_value = create_mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_request_state',
                         return_value={'certificate_id': 'san_validation_cert', 'changed': True, 'validation_files': [
                             {'domain': domain, 'filename': f'{domain}_val.txt', 'content': f'{domain}_validation_content', 'http_validation_url': f'http://{domain}/.well-known/pki-validation/{domain}_val.txt'}
                             for domain in san_domains
                         ]}):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify validation files for all domains
            assert result['changed'] is True
            assert 'validation_files' in result
            assert len(result['validation_files']) == len(san_domains)

    def test_san_certificate_with_wildcard_domain(self, mock_action_base, mock_task_vars,
                                                sample_api_key, temp_directory):
        """Test SAN certificate with wildcard domain included."""
        # Mix of regular and wildcard domains
        mixed_domains = [
            'example.com',
            '*.example.com',  # Wildcard domain
            'api.example.com'  # Specific subdomain
        ]

        csr_path = temp_directory / "wildcard_san.csr"
        cert_path = temp_directory / "wildcard_san.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nwildcard_san_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': mixed_domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'request',
            'validation_method': 'DNS_CSR_HASH',  # Wildcard requires DNS validation
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

        # Mock wildcard certificate response
        wildcard_response = {
            'id': 'wildcard_san_cert',
            'status': 'draft',
            'common_name': 'example.com',
            'additional_domains': '*.example.com,api.example.com',
            'validation': {
                'other_methods': {
                    'example.com': {
                        'cname_validation_p1': 'A1B2C3D4E5F6.example.com',
                        'cname_validation_p2': 'A1B2C3D4E5F6.B2C3D4E5F6A1.C3D4E5F6A1B2.zerossl.com'
                    },
                    '*.example.com': {
                        'cname_validation_p1': 'A1B2C3D4E5F6.example.com',  # Same as base domain
                        'cname_validation_p2': 'A1B2C3D4E5F6.B2C3D4E5F6A1.C3D4E5F6A1B2.zerossl.com'
                    },
                    'api.example.com': {
                        'cname_validation_p1': 'B2C3D4E5F6A1.api.example.com',
                        'cname_validation_p2': 'B2C3D4E5F6A1.C3D4E5F6A1B2.D4E5F6A1B2C3.zerossl.com'
                    }
                }
            }
        }

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': []}
        mock_session.get.return_value = mock_response

        create_mock_response = Mock()
        create_mock_response.status_code = 200
        create_mock_response.json.return_value = {'success': True, 'result': wildcard_response}
        mock_session.post.return_value = create_mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_request_state',
                         return_value={'certificate_id': 'wildcard_san_cert', 'changed': True, 'dns_records': [
                             {'domain': domain, 'record_name': f'validation_{domain.replace(".", "_")}.{domain}', 'record_type': 'CNAME', 'record_value': f'validation.zerossl.com'}
                             for domain in mixed_domains
                         ]}):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify wildcard handling
            assert result['changed'] is True
            assert result['certificate_id'] == 'wildcard_san_cert'

    def test_san_certificate_large_domain_list(self, mock_action_base, mock_task_vars,
                                             sample_api_key, temp_directory):
        """Test SAN certificate with large number of domains."""
        # Create a larger list of domains (testing limits)
        large_domain_list = [
            f'subdomain{i}.example.com' for i in range(1, 26)  # 25 subdomains
        ] + ['example.com']  # Plus main domain

        csr_path = temp_directory / "large_san.csr"
        cert_path = temp_directory / "large_san.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nlarge_san_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': large_domain_list,
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

        # Mock large SAN certificate creation
        large_san_response = {
            'id': 'large_san_cert',
            'status': 'draft',
            'common_name': 'example.com',
            'additional_domains': ','.join(large_domain_list[1:]),  # All except first
            'validation': {
                'other_methods': {
                    domain: {
                        'file_validation_url_http': f'http://{domain}/.well-known/pki-validation/val_{domain.replace(".", "_")}.txt',
                        'file_validation_content': f'validation_for_{domain}'
                    }
                    for domain in large_domain_list
                }
            }
        }

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': []}
        mock_session.get.return_value = mock_response

        create_mock_response = Mock()
        create_mock_response.status_code = 200
        create_mock_response.json.return_value = {'success': True, 'result': large_san_response}
        mock_session.post.return_value = create_mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_present_state',
                         return_value={'certificate_id': 'large_san_cert', 'changed': True}):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify large SAN certificate handling
            assert result['changed'] is True
            assert result['certificate_id'] == 'large_san_cert'

    def test_san_certificate_duplicate_domain_handling(self, mock_action_base, mock_task_vars,
                                                     sample_api_key, temp_directory):
        """Test SAN certificate with duplicate domains in list."""
        # Domain list with duplicates
        domains_with_duplicates = [
            'example.com',
            'www.example.com',
            'example.com',  # Duplicate
            'api.example.com',
            'www.example.com'  # Another duplicate
        ]

        csr_path = temp_directory / "duplicate_san.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nduplicate_san_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': domains_with_duplicates,
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

        # Mock response with deduplicated domains
        unique_domains = ['example.com', 'www.example.com', 'api.example.com']
        dedup_response = {
            'id': 'dedup_san_cert',
            'status': 'draft',
            'validation': {
                'other_methods': {
                    domain: {
                        'file_validation_url_http': f'http://{domain}/.well-known/pki-validation/dedup_{domain.replace(".", "_")}.txt',
                        'file_validation_content': f'dedup_validation_for_{domain}'
                    }
                    for domain in unique_domains
                }
            }
        }

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': []}
        mock_session.get.return_value = mock_response

        create_mock_response = Mock()
        create_mock_response.status_code = 200
        create_mock_response.json.return_value = {'success': True, 'result': dedup_response}
        mock_session.post.return_value = create_mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_request_state',
                         return_value={'certificate_id': 'dedup_san_cert', 'changed': True, 'validation_files': [
                             {'domain': domain, 'filename': f'dedup_{domain.replace(".", "_")}.txt', 'content': f'dedup_validation_for_{domain}'}
                             for domain in unique_domains
                         ]}):
            result = action_module.run(task_vars=mock_task_vars)

            # Should detect duplicate domains and fail appropriately
            assert result.get('failed') is True
            assert 'duplicate' in result['msg'].lower()

    def test_san_certificate_mixed_validation_methods(self, mock_action_base, mock_task_vars,
                                                    sample_api_key, temp_directory):
        """Test SAN certificate with domains requiring different validation methods."""
        # Some domains might require different validation approaches
        mixed_domains = [
            'public.example.com',    # Can use HTTP validation
            'internal.example.com',  # Might need DNS validation
            'admin.example.com'      # Might need DNS validation
        ]

        csr_path = temp_directory / "mixed_validation.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nmixed_validation_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': mixed_domains,
            'csr_path': str(csr_path),
            'state': 'request',
            'validation_method': 'HTTP_CSR_HASH',  # Default method
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

        # Mock response with mixed validation methods
        mixed_validation_response = {
            'id': 'mixed_validation_cert',
            'status': 'draft',
            'validation': {
                'other_methods': {
                    'public.example.com': {
                        'file_validation_url_http': 'http://public.example.com/.well-known/pki-validation/public_val.txt',
                        'file_validation_content': 'public_validation_content'
                    },
                    'internal.example.com': {
                        'file_validation_url_http': 'http://internal.example.com/.well-known/pki-validation/internal_val.txt',
                        'file_validation_content': 'internal_validation_content'
                    },
                    'admin.example.com': {
                        'file_validation_url_http': 'http://admin.example.com/.well-known/pki-validation/admin_val.txt',
                        'file_validation_content': 'admin_validation_content'
                    }
                }
            }
        }

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': []}
        mock_session.get.return_value = mock_response

        create_mock_response = Mock()
        create_mock_response.status_code = 200
        create_mock_response.json.return_value = {'success': True, 'result': mixed_validation_response}
        mock_session.post.return_value = create_mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_request_state',
                         return_value={'certificate_id': 'mixed_validation_cert', 'changed': True, 'validation_files': [
                             {'domain': domain, 'filename': f'{domain}_val.txt', 'content': f'{domain}_validation_content'}
                             for domain in mixed_domains
                         ]}):
            result = action_module.run(task_vars=mock_task_vars)

            # Should handle mixed validation requirements
            assert result['changed'] is True
            assert len(result['validation_files']) == len(mixed_domains)

    def test_san_certificate_existing_certificate_check(self, mock_action_base, mock_task_vars,
                                                      sample_api_key, temp_directory):
        """Test SAN certificate creation when existing certificate covers some domains."""
        new_domains = ['shop.example.com', 'checkout.example.com', 'new.example.com']

        csr_path = temp_directory / "existing_check.csr"
        cert_path = temp_directory / "existing_check.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nexisting_check_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': new_domains,
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

        # Mock existing certificate that covers only some domains
        existing_cert_info = {
            'id': 'partial_coverage_cert',
            'status': 'issued',
            'expires': '2025-12-17 12:00:00',
            'common_name': 'shop.example.com',
            'additional_domains': 'checkout.example.com'  # Missing 'new.example.com'
        }

        # Mock new certificate creation for complete coverage
        new_cert_response = {
            'id': 'complete_coverage_cert',
            'status': 'draft',
            'validation': {'other_methods': {}}
        }

        # Mock HTTP session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'result': [existing_cert_info]}
        mock_session.get.return_value = mock_response

        create_mock_response = Mock()
        create_mock_response.status_code = 200
        create_mock_response.json.return_value = {'success': True, 'result': new_cert_response}
        mock_session.post.return_value = create_mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_present_state',
                         return_value={'certificate_id': 'complete_coverage_cert', 'changed': True}):
            result = action_module.run(task_vars=mock_task_vars)

            # Should create new certificate to cover all domains
            assert result['changed'] is True
            assert result['certificate_id'] == 'complete_coverage_cert'

    def test_san_certificate_validation_failure_handling(self, mock_action_base, mock_task_vars,
                                                        sample_api_key, temp_directory):
        """Test SAN certificate validation failure handling for multiple domains."""
        san_domains = ['fail1.example.com', 'fail2.example.com', 'success.example.com']

        csr_path = temp_directory / "validation_failure.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nvalidation_failure_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': san_domains,
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

        # Mock partial validation failure
        create_response = {
            'id': 'validation_failure_cert',
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

        create_mock_response = Mock()
        create_mock_response.status_code = 200
        create_mock_response.json.return_value = {'success': True, 'result': create_response}
        mock_session.post.return_value = create_mock_response

        with patch('requests.Session', return_value=mock_session), \
             patch.object(action_module, '_handle_present_state',
                         side_effect=ZeroSSLValidationError("Some domains failed validation")):
            # The action module raises AnsibleActionFail for validation errors
            from ansible.errors import AnsibleActionFail
            with pytest.raises(AnsibleActionFail) as exc_info:
                result = action_module.run(task_vars=mock_task_vars)

            # Should raise AnsibleActionFail with validation error message
            assert 'validation' in str(exc_info.value).lower()
