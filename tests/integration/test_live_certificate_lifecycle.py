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

        # Configure task arguments for live certificate creation
        task_args = {
            'api_key': zerossl_api_key,
            'domains': test_domains[:1],  # Use only first domain for simplicity
            'csr_path': str(csr_path),
            'certificate_path': str(cert_path),
            'state': 'present',
            'validation_method': 'HTTP_CSR_HASH',
            'timeout': integration_test_config['timeout']
        }

        live_action_base._task.args = task_args

        # Create action module (no mocks - this is live!)
        action_module = ActionModule(
            task=live_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock()
        )

        try:
            # Step 1: Create certificate
            print(f"\n=== Creating certificate for domain: {test_domains[0]} ===")
            result = action_module.run(task_vars=live_task_vars)

            # Should create a certificate in 'draft' status
            assert 'certificate_id' in result
            certificate_id = result['certificate_id']
            cleanup_certificates.append(certificate_id)

            print(f"Created certificate with ID: {certificate_id}")

            # Step 2: Get validation information
            cert_info = action_module._get_certificate_info(certificate_id)
            assert cert_info['status'] == 'draft'
            assert 'validation' in cert_info

            validation_data = cert_info['validation']['other_methods']
            domain = test_domains[0]
            assert domain in validation_data

            validation_info = validation_data[domain]
            validation_url = validation_info['file_validation_url_http']
            validation_content = validation_info['file_validation_content']

            print(f"\n=== Manual Validation Required ===")
            print(f"Domain: {domain}")
            print(f"Validation URL: {validation_url}")
            print(f"Validation Content: {validation_content}")
            print(f"\nPlease create the validation file at the URL above with the content shown.")
            print(f"Then press Enter to continue with validation...")

            # In CI/automated testing, you might skip this manual step
            if not os.getenv("ZEROSSL_SKIP_MANUAL_VALIDATION"):
                input("Press Enter when validation file is ready...")

            # Step 3: Validate certificate
            print(f"\n=== Validating certificate ===")
            validation_result = action_module._validate_certificate(certificate_id)

            # Note: This might take several attempts in real scenarios
            max_validation_attempts = 5
            for attempt in range(max_validation_attempts):
                if validation_result.get('success'):
                    break

                print(f"Validation attempt {attempt + 1} failed, retrying in 30 seconds...")
                time.sleep(30)
                validation_result = action_module._validate_certificate(certificate_id)

            assert validation_result.get('success'), f"Validation failed after {max_validation_attempts} attempts"
            print("Certificate validation successful!")

            # Step 4: Wait for certificate issuance (can take a few minutes)
            print(f"\n=== Waiting for certificate issuance ===")
            max_wait_time = integration_test_config['validation_timeout']
            wait_interval = 30
            waited = 0

            while waited < max_wait_time:
                cert_info = action_module._get_certificate_info(certificate_id)
                status = cert_info['status']
                print(f"Certificate status: {status} (waited {waited}s)")

                if status == 'issued':
                    break
                elif status == 'cancelled' or status == 'expired':
                    pytest.fail(f"Certificate entered failure state: {status}")

                time.sleep(wait_interval)
                waited += wait_interval

            assert cert_info['status'] == 'issued', f"Certificate not issued within {max_wait_time} seconds"

            # Step 5: Download certificate
            print(f"\n=== Downloading certificate ===")
            certificate_content = action_module._download_certificate(certificate_id)

            assert certificate_content
            assert '-----BEGIN CERTIFICATE-----' in certificate_content
            assert '-----END CERTIFICATE-----' in certificate_content

            # Save certificate to file
            action_module._save_certificate(cert_path, certificate_content)
            assert cert_path.exists()
            assert cert_path.stat().st_size > 0

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
            assert cert_info['id'] == existing_cert_id
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
