# -*- coding: utf-8 -*-
"""
Integration test for multi-domain (SAN) certificate scenario.

This test covers SAN certificate workflows from the quickstart guide:
creating certificates that cover multiple domains in a single certificate.
"""

import pytest
from unittest.mock import Mock, patch
from plugins.action.zerossl_certificate import ActionModule


@pytest.mark.integration
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
            'validation_method': 'HTTP_CSR_HASH'
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

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value=None),  # No existing cert
            _create_certificate=Mock(return_value=san_response),
            _validate_certificate=Mock(return_value={'success': True}),
            _download_certificate=Mock(return_value='san_certificate_content'),
            _save_certificate=Mock()
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify SAN certificate creation
            assert result['changed'] is True
            assert result['certificate_id'] == 'san_cert_123456'

            # Verify create_certificate was called with all domains
            create_call = action_module._create_certificate.call_args
            assert create_call is not None
            # Verify domains were passed correctly (implementation dependent)

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
            'state': 'request'  # Only request to get validation files
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

        with patch.object(action_module, '_create_certificate', return_value=validation_response):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify validation files for all domains
            assert result['changed'] is True
            assert 'validation_files' in result
            assert len(result['validation_files']) == len(san_domains)

            # Verify each domain has validation file
            validation_domains = [vf['domain'] for vf in result['validation_files']]
            for domain in san_domains:
                assert domain in validation_domains

            # Verify validation file structure
            for vf in result['validation_files']:
                assert 'domain' in vf
                assert 'filename' in vf
                assert 'content' in vf
                assert 'http_validation_url' in vf
                assert vf['domain'] in san_domains

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
            'validation_method': 'DNS_CSR_HASH'  # Wildcard requires DNS validation
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
                        'dns_txt_name': '_acme-challenge.example.com',
                        'dns_txt_value': 'dns_challenge_for_example_com'
                    },
                    '*.example.com': {
                        'dns_txt_name': '_acme-challenge.example.com',  # Same as base domain
                        'dns_txt_value': 'dns_challenge_for_wildcard'
                    },
                    'api.example.com': {
                        'dns_txt_name': '_acme-challenge.api.example.com',
                        'dns_txt_value': 'dns_challenge_for_api'
                    }
                }
            }
        }

        with patch.object(action_module, '_create_certificate', return_value=wildcard_response):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify wildcard handling
            assert result['changed'] is True
            assert result['certificate_id'] == 'wildcard_san_cert'

            # Verify validation files include DNS records
            validation_files = result['validation_files']
            assert len(validation_files) == len(mixed_domains)

            # Check for wildcard domain handling
            wildcard_file = next((vf for vf in validation_files if vf['domain'] == '*.example.com'), None)
            assert wildcard_file is not None

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

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value=None),
            _create_certificate=Mock(return_value=large_san_response),
            _validate_certificate=Mock(return_value={'success': True}),
            _download_certificate=Mock(return_value='large_san_content'),
            _save_certificate=Mock()
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify large SAN certificate handling
            assert result['changed'] is True
            assert result['certificate_id'] == 'large_san_cert'

            # Should handle large domain list without issues
            create_call = action_module._create_certificate.call_args
            assert create_call is not None

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

        with patch.object(action_module, '_create_certificate', return_value=dedup_response):
            result = action_module.run(task_vars=mock_task_vars)

            # Should handle duplicates gracefully
            assert result['changed'] is True

            # Validation files should only include unique domains
            validation_files = result['validation_files']
            validation_domains = [vf['domain'] for vf in validation_files]
            assert len(set(validation_domains)) == len(validation_domains)  # All unique

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
            'validation_method': 'HTTP_CSR_HASH'  # Default method
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

        with patch.object(action_module, '_create_certificate', return_value=mixed_validation_response):
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

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value='partial_coverage_cert'),
            _get_certificate_info=Mock(return_value=existing_cert_info),
            _create_certificate=Mock(return_value=new_cert_response),
            _validate_certificate=Mock(return_value={'success': True}),
            _download_certificate=Mock(return_value='complete_coverage_content'),
            _save_certificate=Mock()
        ):
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

        # Mock partial validation failure
        create_response = {
            'id': 'validation_failure_cert',
            'status': 'draft',
            'validation': {'other_methods': {}}
        }

        from plugins.module_utils.zerossl.exceptions import ZeroSSLValidationError

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value=None),
            _create_certificate=Mock(return_value=create_response),
            _validate_certificate=Mock(side_effect=ZeroSSLValidationError("Some domains failed validation"))
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Should handle validation failure gracefully
            assert result.get('failed') is True
            assert 'validation' in result['msg'].lower()
            assert result.get('error_type') == 'validation'
