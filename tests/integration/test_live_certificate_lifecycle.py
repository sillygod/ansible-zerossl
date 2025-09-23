# -*- coding: utf-8 -*-
"""
Live integration test for complete certificate lifecycle.

This test performs actual API calls to ZeroSSL and validates the complete
certificate management workflow end-to-end.

Requirements:
- ZEROSSL_API_KEY environment variable
- ZEROSSL_TEST_DOMAINS environment variable (domains you control)
- Network connectivity
- Ability to place validation files on test domains
"""

import pytest
import time
import os
from pathlib import Path
from unittest.mock import Mock
from plugins.action.zerossl_certificate import ActionModule
from plugins.module_utils.zerossl.utils import generate_csr


@pytest.mark.integration
@pytest.mark.live
@pytest.mark.slow
class TestLiveCertificateLifecycle:
    """Test real certificate lifecycle with ZeroSSL API."""

    def test_create_and_validate_certificate_http(
        self,
        zerossl_api_key,
        test_domains,
        live_action_base,
        live_task_vars,
        temp_cert_directory,
        cleanup_certificates,
        integration_test_config
    ):
        """
        Test creating and validating a real certificate using HTTP validation.

        This is a full end-to-end test that:
        1. Creates a real certificate request with ZeroSSL
        2. Retrieves validation challenges
        3. Guides user through manual validation setup
        4. Validates the certificate
        5. Downloads the issued certificate
        """
        # Setup test files
        csr_path = temp_cert_directory / "test_live.csr"
        cert_path = temp_cert_directory / "test_live.crt"
        key_path = temp_cert_directory / "test_live.key"

        # Generate a real CSR for testing
        self._generate_test_csr(csr_path, key_path, test_domains[0])

        try:
            # Step 1: Request certificate (state='request')
            print(f"\n=== Step 1: Requesting certificate for domain: {test_domains[0]} ===")

            # Configure task arguments for certificate request
            request_task_args = {
                'api_key': zerossl_api_key,
                'domains': test_domains[:1],  # Use only first domain for simplicity
                'csr_path': str(csr_path),
                'state': 'request',
                'validation_method': 'HTTP_CSR_HASH',
                'file_mode': '0644',
                'timeout': integration_test_config['timeout']
            }

            live_action_base._task.args = request_task_args

            # Create action module (no mocks - this is live!)
            action_module = ActionModule(
                task=live_action_base._task,
                connection=Mock(),
                play_context=Mock(),
                loader=Mock(),
                templar=Mock(),
                shared_loader_obj=Mock()
            )

            # Request certificate
            result = action_module.run(task_vars=live_task_vars)

            # Should create a certificate in 'draft' status with validation info
            assert 'certificate_id' in result
            assert result['changed'] is True
            certificate_id = result['certificate_id']
            cleanup_certificates.append(certificate_id)

            print(f"Created certificate request with ID: {certificate_id}")
            print(f"Certificate status: {result.get('status', 'unknown')}")

            # Should have validation files for HTTP validation
            assert 'validation_files' in result
            assert len(result['validation_files']) > 0

            validation_file = result['validation_files'][0]
            print(f"\n=== Step 2: Manual Validation Required ===")
            print(f"Domain: {validation_file['domain']}")
            print(f"Validation File: {validation_file['filename']}")
            print(f"Validation Content: {validation_file['content']}")
            print(f"File Path: {validation_file.get('file_path', 'N/A')}")
            print(f"\nPlease create the validation file at the path above with the content shown.")
            print(f"Then press Enter to continue with validation...")

            # In CI/automated testing, you might skip this manual step
            if not os.getenv("ZEROSSL_SKIP_MANUAL_VALIDATION"):
                input("Press Enter when validation file is ready...")

            # Step 3: Validate certificate (state='validate')
            print(f"\n=== Step 3: Validating certificate ===")

            # Configure task arguments for validation
            validate_task_args = {
                'api_key': zerossl_api_key,
                'certificate_id': certificate_id,
                'state': 'validate',
                'validation_method': 'HTTP_CSR_HASH',
                'timeout': integration_test_config['timeout']
            }

            live_action_base._task.args = validate_task_args

            validation_result = action_module.run(task_vars=live_task_vars)

            # Note: This might take several attempts in real scenarios
            max_validation_attempts = 5
            for attempt in range(max_validation_attempts):
                if validation_result.get('validation_result', {}).get('success'):
                    break

                print(f"Validation attempt {attempt + 1} failed, retrying in 30 seconds...")
                time.sleep(30)
                validation_result = action_module.run(task_vars=live_task_vars)

            assert validation_result.get('validation_result', {}).get('success'), f"Validation failed after {max_validation_attempts} attempts"
            print("Certificate validation triggered successfully!")

            # Step 4: Wait for certificate issuance (polling status)
            print(f"\n=== Step 4: Waiting for certificate issuance ===")
            max_wait_time = integration_test_config['validation_timeout']
            wait_interval = 30
            waited = 0

            # Use the certificate manager to poll status
            from plugins.module_utils.zerossl.api_client import ZeroSSLAPIClient
            from plugins.module_utils.zerossl.certificate_manager import CertificateManager

            api_client = ZeroSSLAPIClient(zerossl_api_key)
            cert_manager = CertificateManager(zerossl_api_key, api_client)

            while waited < max_wait_time:
                cert_info = cert_manager.get_certificate_status(certificate_id)
                status = cert_info['status']
                print(f"Certificate status: {status} (waited {waited}s)")

                if status == 'issued':
                    break
                elif status in ['cancelled', 'expired', 'failed']:
                    pytest.fail(f"Certificate entered failure state: {status}")

                time.sleep(wait_interval)
                waited += wait_interval

            assert cert_info['status'] == 'issued', f"Certificate not issued within {max_wait_time} seconds"

            # Step 5: Download certificate (state='download')
            print(f"\n=== Step 5: Downloading certificate ===")

            # Configure task arguments for download
            download_task_args = {
                'api_key': zerossl_api_key,
                'certificate_id': certificate_id,
                'certificate_path': str(cert_path),
                'private_key_path': str(key_path),
                'state': 'download',
                'file_mode': '0644',
                'timeout': integration_test_config['timeout']
            }

            live_action_base._task.args = download_task_args

            download_result = action_module.run(task_vars=live_task_vars)

            assert download_result['changed'] is True
            assert 'files_created' in download_result
            assert str(cert_path) in download_result['files_created']

            # Verify certificate file was created
            assert cert_path.exists()
            assert cert_path.stat().st_size > 0

            # Verify certificate content
            cert_content = cert_path.read_text()
            assert '-----BEGIN CERTIFICATE-----' in cert_content
            assert '-----END CERTIFICATE-----' in cert_content

            print(f"Certificate successfully downloaded to: {cert_path}")
            print(f"Certificate ID: {certificate_id}")
            print("=== Live integration test completed successfully! ===")

        except Exception as e:
            print(f"\n=== Live integration test failed ===")
            print(f"Error: {e}")
            if 'certificate_id' in locals():
                print(f"Certificate ID (for manual cleanup): {certificate_id}")
            raise

    def test_existing_certificate_check(
        self,
        zerossl_api_key,
        test_domains,
        live_action_base,
        live_task_vars,
        temp_cert_directory
    ):
        """
        Test checking for existing certificates (idempotent behavior).

        This test verifies that the plugin correctly identifies existing
        certificates and doesn't create duplicates.
        """
        # Setup test files
        csr_path = temp_cert_directory / "existing_check.csr"
        cert_path = temp_cert_directory / "existing_check.crt"
        key_path = temp_cert_directory / "existing_check.key"

        self._generate_test_csr(csr_path, key_path, test_domains[0])

        task_args = {
            'api_key': zerossl_api_key,
            'domains': test_domains[:1],
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'present'
        }

        live_action_base._task.args = task_args

        action_module = ActionModule(
            task=live_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        # Check for existing certificates
        print(f"\n=== Checking for existing certificates ===")
        existing_cert_id = action_module._get_certificate_id(test_domains[0])

        if existing_cert_id:
            print(f"Found existing certificate: {existing_cert_id}")

            # Get certificate info
            cert_info = action_module._get_certificate_info(existing_cert_id)
            print(f"Certificate status: {cert_info['status']}")
            print(f"Certificate expires: {cert_info.get('expires', 'Unknown')}")

            # Test that plugin properly identifies existing certificate
            assert cert_info['certificate_id'] == existing_cert_id
        else:
            print("No existing certificate found - this is expected for fresh test domains")

        print("=== Existing certificate check completed ===")

    def _generate_test_csr(self, csr_path: Path, key_path: Path, domain: str):
        """
        Generate a test CSR and private key for the given domain.

        This is a helper method to create realistic test data.
        """
        try:
            # Use the existing generate_csr utility function
            csr_content, private_key_content = generate_csr([domain])

            # Save CSR
            with open(csr_path, "w") as f:
                f.write(csr_content)

            # Save private key
            with open(key_path, "w") as f:
                f.write(private_key_content)

            print(f"Generated test CSR and key for domain: {domain}")

        except Exception as e:
            # If CSR generation fails, skip the test
            pytest.skip(f"Cannot generate CSR: {e}")


@pytest.mark.integration
@pytest.mark.live
class TestLiveAPIConnectivity:
    """Test basic API connectivity and authentication."""

    def test_api_authentication(self, zerossl_api_key):
        """Test that API key works and we can authenticate."""
        from plugins.module_utils.zerossl.api_client import ZeroSSLAPIClient

        client = ZeroSSLAPIClient(zerossl_api_key)

        # Test basic API call - list certificates
        response = client.list_certificates()

        # Should not raise an exception and should return valid data
        assert isinstance(response, (list, dict))
        print(f"API authentication successful. Account has {len(response) if isinstance(response, list) else 'unknown'} certificates.")

    def test_api_rate_limits(self, zerossl_api_key):
        """Test that API client handles rate limits gracefully."""
        from plugins.module_utils.zerossl.api_client import ZeroSSLAPIClient

        client = ZeroSSLAPIClient(zerossl_api_key)

        # Make several rapid API calls to test rate limiting
        for i in range(3):
            try:
                response = client.list_certificates()
                print(f"API call {i + 1} successful")
                time.sleep(1)  # Small delay between calls
            except Exception as e:
                if "rate limit" in str(e).lower():
                    print(f"Rate limit encountered on call {i + 1}: {e}")
                    break
                else:
                    raise
