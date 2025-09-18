# -*- coding: utf-8 -*-
"""
Integration test for DNS validation workflow.

This test covers DNS-01 validation workflows including wildcard certificates
and DNS record management from the quickstart guide.
"""

import pytest
from unittest.mock import Mock, patch
from plugins.action.zerossl_certificate import ActionModule


@pytest.mark.integration
class TestDNSValidationWorkflow:
    """Test DNS-01 validation workflows."""

    def test_wildcard_certificate_dns_validation(self, mock_action_base, mock_task_vars,
                                                sample_api_key, temp_directory):
        """Test wildcard certificate with DNS validation."""
        # Wildcard domains require DNS validation
        wildcard_domains = ['*.example.com', 'example.com']

        csr_path = temp_directory / "wildcard.csr"
        cert_path = temp_directory / "wildcard.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nwildcard_csr_content\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': wildcard_domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'request',
            'validation_method': 'DNS_CSR_HASH'
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

        # Mock DNS validation response
        dns_response = {
            'certificate_id': 'wildcard_dns_cert',
            'status': 'draft',
            'domains': wildcard_domains,
            'common_name': 'example.com',
            'additional_domains': '*.example.com',
            'validation': {
                'other_methods': {
                    'example.com': {
                        'dns_txt_name': '_acme-challenge.example.com',
                        'dns_txt_value': 'dns_challenge_token_base_domain'
                    },
                    '*.example.com': {
                        'dns_txt_name': '_acme-challenge.example.com',  # Same as base domain
                        'dns_txt_value': 'dns_challenge_token_wildcard'
                    }
                }
            },
            'dns_records': [
                {
                    'name': '_acme-challenge.example.com',
                    'type': 'TXT',
                    'value': 'dns_challenge_token_base_domain'
                },
                {
                    'name': '_acme-challenge.example.com',
                    'type': 'TXT',
                    'value': 'dns_challenge_token_wildcard'
                }
            ]
        }

        with patch('plugins.module_utils.zerossl.certificate_manager.CertificateManager.create_certificate', return_value=dns_response):
            result = action_module.run(task_vars=mock_task_vars)

            # Verify DNS validation structure
            assert result['changed'] is True
            assert result['certificate_id'] == 'wildcard_dns_cert'
            assert 'dns_records' in result

            # Check DNS records structure
            dns_records = result['dns_records']
            assert len(dns_records) == len(wildcard_domains)  # One record per domain

            for record in dns_records:
                assert 'name' in record
                assert 'type' in record
                assert 'value' in record
                assert record['type'] == 'TXT'
                assert record['name'].startswith('_acme-challenge.')
                assert len(record['value']) > 0

    def test_dns_validation_record_instructions(self, mock_action_base, mock_task_vars,
                                              sample_api_key, temp_directory):
        """Test DNS validation provides clear record instructions."""
        domains = ['dns.example.com']

        csr_path = temp_directory / "dns_instructions.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ndns_instructions_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': domains,
            'csr_path': str(csr_path),
            'state': 'request',
            'validation_method': 'DNS_CSR_HASH'
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

        dns_response = {
            'certificate_id': 'dns_instructions_cert',
            'status': 'draft',
            'domains': domains,
            'validation': {
                'other_methods': {
                    'dns.example.com': {
                        'dns_txt_name': '_acme-challenge.dns.example.com',
                        'dns_txt_value': 'very_long_dns_challenge_token_1234567890abcdef'
                    }
                }
            },
            'dns_records': [
                {
                    'name': '_acme-challenge.dns.example.com',
                    'type': 'TXT',
                    'value': 'very_long_dns_challenge_token_1234567890abcdef'
                }
            ]
        }

        with patch('plugins.module_utils.zerossl.certificate_manager.CertificateManager.create_certificate', return_value=dns_response):
            result = action_module.run(task_vars=mock_task_vars)

            # Should provide clear DNS instructions
            dns_records = result['dns_records']
            dns_record = dns_records[0]

            assert dns_record['name'] == '_acme-challenge.dns.example.com'
            assert dns_record['type'] == 'TXT'
            assert dns_record['value'] == 'very_long_dns_challenge_token_1234567890abcdef'

    def test_multiple_dns_records_for_san(self, mock_action_base, mock_task_vars,
                                        sample_api_key, temp_directory):
        """Test multiple DNS records for SAN certificate with DNS validation."""
        # Multiple subdomains requiring DNS validation
        dns_domains = [
            'internal.example.com',
            'private.example.com',
            'secure.example.com'
        ]

        csr_path = temp_directory / "multiple_dns.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nmultiple_dns_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': dns_domains,
            'csr_path': str(csr_path),
            'state': 'request',
            'validation_method': 'DNS_CSR_HASH'
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

        # Mock multiple DNS records response
        multiple_dns_response = {
            'certificate_id': 'multiple_dns_cert',
            'status': 'draft',
            'domains': dns_domains,
            'validation': {
                'other_methods': {
                    domain: {
                        'dns_txt_name': f'_acme-challenge.{domain}',
                        'dns_txt_value': f'dns_token_for_{domain.replace(".", "_")}'
                    }
                    for domain in dns_domains
                }
            },
            'dns_records': [
                {
                    'name': f'_acme-challenge.{domain}',
                    'type': 'TXT',
                    'value': f'dns_token_for_{domain.replace(".", "_")}'
                }
                for domain in dns_domains
            ]
        }

        with patch('plugins.module_utils.zerossl.certificate_manager.CertificateManager.create_certificate', return_value=multiple_dns_response):
            result = action_module.run(task_vars=mock_task_vars)

            # Should create DNS record for each domain
            dns_records = result['dns_records']
            assert len(dns_records) == len(dns_domains)

            # Verify each domain has unique DNS record
            dns_names = [record['name'] for record in dns_records]
            assert len(set(dns_names)) == len(dns_names)  # All unique

            for record in dns_records:
                assert record['type'] == 'TXT'
                assert record['name'].startswith('_acme-challenge.')
                # Extract domain from record name and verify token contains domain reference
                domain_part = record['name'].replace('_acme-challenge.', '')
                assert domain_part.replace(".", "_") in record['value']

    def test_dns_validation_with_existing_records(self, mock_action_base, mock_task_vars,
                                                sample_api_key, temp_directory):
        """Test DNS validation workflow when DNS records might already exist."""
        domains = ['existing-dns.example.com']

        csr_path = temp_directory / "existing_dns.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nexisting_dns_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': domains,
            'csr_path': str(csr_path),
            'state': 'request',
            'validation_method': 'DNS_CSR_HASH'
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

        dns_response = {
            'certificate_id': 'existing_dns_cert',
            'status': 'draft',
            'domains': domains,
            'validation': {
                'other_methods': {
                    'existing-dns.example.com': {
                        'dns_txt_name': '_acme-challenge.existing-dns.example.com',
                        'dns_txt_value': 'new_dns_challenge_token_replaces_old'
                    }
                }
            },
            'dns_records': [
                {
                    'name': '_acme-challenge.existing-dns.example.com',
                    'type': 'TXT',
                    'value': 'new_dns_challenge_token_replaces_old'
                }
            ]
        }

        with patch('plugins.module_utils.zerossl.certificate_manager.CertificateManager.create_certificate', return_value=dns_response):
            result = action_module.run(task_vars=mock_task_vars)

            # Should provide instructions for updating/replacing existing records
            dns_records = result['dns_records']
            dns_record = dns_records[0]

            # Should include guidance about replacing existing records
            assert dns_record['value'] == 'new_dns_challenge_token_replaces_old'

    def test_dns_validation_timeout_handling(self, mock_action_base, mock_task_vars,
                                           sample_api_key, temp_directory):
        """Test DNS validation with timeout scenarios."""
        domains = ['slow-dns.example.com']

        csr_path = temp_directory / "dns_timeout.csr"
        cert_path = temp_directory / "dns_timeout.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ndns_timeout_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'present',
            'validation_method': 'DNS_CSR_HASH'
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

        # Mock DNS validation timeout
        create_response = {
            'certificate_id': 'dns_timeout_cert',
            'status': 'draft',
            'domains': domains,
            'validation': {'other_methods': {}},
            'dns_records': []
        }

        from plugins.module_utils.zerossl.exceptions import ZeroSSLValidationError
        import pytest

        with patch('plugins.module_utils.zerossl.certificate_manager.CertificateManager.create_certificate', return_value=create_response):
            with patch('plugins.module_utils.zerossl.certificate_manager.CertificateManager.poll_validation_status', side_effect=ZeroSSLValidationError("DNS validation timeout")):
                # This should raise an exception rather than return a failed result
                with pytest.raises(Exception) as exc_info:
                    action_module.run(task_vars=mock_task_vars)

                # Should handle DNS timeout gracefully by raising appropriate exception
                assert 'timeout' in str(exc_info.value).lower() or 'validation' in str(exc_info.value).lower()

    def test_wildcard_and_specific_domain_combination(self, mock_action_base, mock_task_vars,
                                                    sample_api_key, temp_directory):
        """Test wildcard domain combined with specific subdomains."""
        # Combination that might have overlapping coverage
        combined_domains = [
            'example.com',
            '*.example.com',
            'api.example.com',  # Covered by wildcard but explicitly listed
            'www.example.com'   # Also covered by wildcard
        ]

        csr_path = temp_directory / "wildcard_specific.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nwildcard_specific_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': combined_domains,
            'csr_path': str(csr_path),
            'state': 'request',
            'validation_method': 'DNS_CSR_HASH'
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

        # Mock response handling overlapping domains
        combined_response = {
            'certificate_id': 'wildcard_specific_cert',
            'status': 'draft',
            'domains': combined_domains,
            'validation': {
                'other_methods': {
                    'example.com': {
                        'dns_txt_name': '_acme-challenge.example.com',
                        'dns_txt_value': 'base_domain_token'
                    },
                    '*.example.com': {
                        'dns_txt_name': '_acme-challenge.example.com',  # Same as base
                        'dns_txt_value': 'wildcard_token'
                    },
                    'api.example.com': {
                        'dns_txt_name': '_acme-challenge.api.example.com',
                        'dns_txt_value': 'api_specific_token'
                    },
                    'www.example.com': {
                        'dns_txt_name': '_acme-challenge.www.example.com',
                        'dns_txt_value': 'www_specific_token'
                    }
                }
            },
            'dns_records': [
                {
                    'name': '_acme-challenge.example.com',
                    'type': 'TXT',
                    'value': 'base_domain_token'
                },
                {
                    'name': '_acme-challenge.example.com',
                    'type': 'TXT',
                    'value': 'wildcard_token'
                },
                {
                    'name': '_acme-challenge.api.example.com',
                    'type': 'TXT',
                    'value': 'api_specific_token'
                },
                {
                    'name': '_acme-challenge.www.example.com',
                    'type': 'TXT',
                    'value': 'www_specific_token'
                }
            ]
        }

        with patch('plugins.module_utils.zerossl.certificate_manager.CertificateManager.create_certificate', return_value=combined_response):
            result = action_module.run(task_vars=mock_task_vars)

            # Should handle overlapping domains appropriately
            dns_records = result['dns_records']
            assert len(dns_records) == len(combined_domains)

            # Check that base domain and wildcard both reference same challenge name
            base_domain_records = [r for r in dns_records if r['value'] == 'base_domain_token']
            wildcard_records = [r for r in dns_records if r['value'] == 'wildcard_token']

            assert len(base_domain_records) == 1
            assert len(wildcard_records) == 1
            assert base_domain_records[0]['name'] == wildcard_records[0]['name']  # Same challenge name

    def test_dns_propagation_verification(self, mock_action_base, mock_task_vars,
                                        sample_api_key, temp_directory):
        """Test DNS propagation verification before validation."""
        domains = ['propagation.example.com']

        csr_path = temp_directory / "propagation.csr"
        cert_path = temp_directory / "propagation.crt"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\npropagation_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': domains,
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'present',
            'validation_method': 'DNS_CSR_HASH'
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

        # Mock successful DNS workflow
        create_response = {
            'id': 'propagation_cert',
            'status': 'draft',
            'validation': {'other_methods': {}}
        }

        with patch.multiple(
            action_module,
            _get_certificate_id=Mock(return_value=None),
            _create_certificate=Mock(return_value=create_response),
            _validate_certificate=Mock(return_value={'success': True}),
            _download_certificate=Mock(return_value='propagation_cert_content'),
            _save_certificate=Mock()
        ):
            result = action_module.run(task_vars=mock_task_vars)

            # Should complete DNS validation workflow
            assert result['changed'] is True
            assert result['certificate_id'] == 'propagation_cert'

    def test_dns_validation_split_workflow(self, mock_action_base, mock_task_vars,
                                         sample_api_key, temp_directory):
        """Test DNS validation in split workflow (request → manual DNS → validate)."""
        domains = ['split-dns.example.com']

        csr_path = temp_directory / "split_dns.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\nsplit_dns_csr\n-----END CERTIFICATE REQUEST-----")

        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Step 1: Request with DNS validation
        mock_action_base._task.args = {
            'api_key': sample_api_key,
            'domains': domains,
            'csr_path': str(csr_path),
            'state': 'request',
            'validation_method': 'DNS_CSR_HASH'
        }

        dns_request_response = {
            'id': 'split_dns_cert',
            'status': 'draft',
            'validation': {
                'other_methods': {
                    'split-dns.example.com': {
                        'dns_txt_name': '_acme-challenge.split-dns.example.com',
                        'dns_txt_value': 'split_dns_challenge_token'
                    }
                }
            }
        }

        with patch.object(action_module, '_create_certificate', return_value=dns_request_response):
            request_result = action_module.run(task_vars=mock_task_vars)
            certificate_id = request_result['certificate_id']

        # Verify DNS instructions were provided
        assert request_result['changed'] is True
        assert len(request_result['validation_files']) == 1
        dns_file = request_result['validation_files'][0]
        assert dns_file['dns_record']['name'] == '_acme-challenge.split-dns.example.com'
        assert dns_file['dns_record']['value'] == 'split_dns_challenge_token'

        # Step 2: Validate (after manual DNS record creation)
        mock_action_base._task.args = {
            'api_key': sample_api_key,
            'certificate_id': certificate_id,
            'state': 'validate',
            'validation_method': 'DNS_CSR_HASH'
        }

        with patch.object(action_module, '_validate_certificate',
                         return_value={'success': True, 'validation_completed': True}):
            validate_result = action_module.run(task_vars=mock_task_vars)

        # Should complete validation
        assert validate_result['changed'] is True
        assert validate_result['validation_result']['success'] is True

    def test_dns_validation_error_scenarios(self, mock_action_base, mock_task_vars,
                                          sample_api_key, temp_directory):
        """Test various DNS validation error scenarios."""
        domains = ['error-dns.example.com']

        csr_path = temp_directory / "dns_errors.csr"
        csr_path.write_text("-----BEGIN CERTIFICATE REQUEST-----\ndns_errors_csr\n-----END CERTIFICATE REQUEST-----")

        task_args = {
            'api_key': sample_api_key,
            'domains': domains,
            'csr_path': str(csr_path),
            'state': 'present',
            'validation_method': 'DNS_CSR_HASH'
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

        # Test different DNS validation errors
        error_scenarios = [
            "DNS record not found",
            "Incorrect DNS record value",
            "DNS propagation timeout",
            "DNS server unreachable"
        ]

        create_response = {
            'id': 'dns_error_cert',
            'status': 'draft',
            'validation': {'other_methods': {}}
        }

        for error_msg in error_scenarios:
            from plugins.module_utils.zerossl.exceptions import ZeroSSLValidationError

            with patch.multiple(
                action_module,
                _get_certificate_id=Mock(return_value=None),
                _create_certificate=Mock(return_value=create_response),
                _validate_certificate=Mock(side_effect=ZeroSSLValidationError(error_msg))
            ):
                result = action_module.run(task_vars=mock_task_vars)

                # Should handle each DNS error appropriately
                assert result.get('failed') is True
                assert result.get('error_type') == 'validation'
                # Error message should contain DNS-related information
                assert any(keyword in result['msg'].lower() for keyword in ['dns', 'record', 'validation'])
