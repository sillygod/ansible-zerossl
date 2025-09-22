# -*- coding: utf-8 -*-
"""
Live API contract tests for ZeroSSL integration.

These tests verify that the ZeroSSL API behaves as expected and that
our integration handles real API responses correctly.
"""

import pytest
import json
from plugins.module_utils.zerossl.api_client import ZeroSSLAPIClient
from plugins.module_utils.zerossl.exceptions import ZeroSSLHTTPError
from plugins.module_utils.zerossl.utils import generate_csr


@pytest.mark.integration
@pytest.mark.live
class TestLiveZeroSSLAPIContract:
    """Test real ZeroSSL API contract compliance."""

    def test_list_certificates_response_format(self, zerossl_api_key):
        """Test that list_certificates returns expected format."""
        client = ZeroSSLAPIClient(zerossl_api_key)
        response = client.list_certificates()

        # Should be a list or dict with expected structure
        assert isinstance(response, (list, dict))

        if isinstance(response, list):
            # If list, each item should be a certificate
            for cert in response[:3]:  # Check first 3 to avoid rate limits
                self._validate_certificate_structure(cert)
        else:
            # If dict, might be paginated response
            if 'results' in response:
                for cert in response['results'][:3]:
                    self._validate_certificate_structure(cert)

    def test_create_certificate_validation_response(
        self,
        zerossl_api_key,
        test_domains,
        temp_cert_directory
    ):
        """Test certificate creation returns proper validation data."""
        # Skip this test if we're at API limits
        if self._should_skip_create_test():
            pytest.skip("Skipping certificate creation to avoid API limits")

        client = ZeroSSLAPIClient(zerossl_api_key)

        # Generate a test CSR
        csr_path = temp_cert_directory / "contract_test.csr"
        key_path = temp_cert_directory / "contract_test.key"
        self._generate_simple_csr(csr_path, test_domains[0])

        with open(csr_path, 'r') as f:
            csr_content = f.read()

        try:
            # Create certificate
            response = client.create_certificate(
                domains=test_domains[:1],
                csr=csr_content
            )

            # Validate response structure
            assert 'id' in response
            assert 'status' in response
            assert response['status'] == 'draft'

            # Should have validation data
            assert 'validation' in response
            validation = response['validation']

            # Should have other_methods for HTTP validation
            assert 'other_methods' in validation
            other_methods = validation['other_methods']

            # Should have validation data for our domain
            domain = test_domains[0]
            assert domain in other_methods

            domain_validation = other_methods[domain]
            assert 'file_validation_url_http' in domain_validation
            assert 'file_validation_content' in domain_validation

            # Validation URL should be properly formatted
            validation_url = domain_validation['file_validation_url_http']
            assert validation_url.startswith(f'http://{domain}/')
            assert '.well-known/pki-validation/' in validation_url

            # Validation content should be non-empty string
            validation_content = domain_validation['file_validation_content']
            assert isinstance(validation_content, list)
            assert len(validation_content) > 0

            print(f"Certificate creation contract test passed. ID: {response['id']}")

        except ZeroSSLHTTPError as e:
            if "quota" in str(e).lower() or "limit" in str(e).lower():
                pytest.skip(f"API quota/limit reached: {e}")
            raise

    def test_certificate_info_response_format(self, zerossl_api_key):
        """Test get_certificate returns expected format."""
        client = ZeroSSLAPIClient(zerossl_api_key)

        # Get list of certificates first
        certificates = client.list_certificates()

        if not certificates:
            pytest.skip("No certificates available to test info format")

        # Get first certificate ID
        if isinstance(certificates, list):
            if not certificates:
                pytest.skip("No certificates in list")
            cert_id = certificates[0]['id']
        else:
            if 'results' not in certificates or not certificates['results']:
                pytest.skip("No certificates in results")
            cert_id = certificates['results'][0]['id']

        # Get certificate info
        cert_info = client.get_certificate(cert_id)

        # Validate structure
        self._validate_certificate_structure(cert_info)

        # Should have additional fields for detailed info
        assert 'id' in cert_info
        assert cert_info['id'] == cert_id

    def test_invalid_api_key_handling(self):
        """Test that invalid API key produces proper error."""
        client = ZeroSSLAPIClient("invalid_api_key_12345")

        with pytest.raises(ZeroSSLHTTPError) as exc_info:
            client.list_certificates()

        error = exc_info.value
        assert "401" in str(error).lower() or "unauthorized" in str(error).lower()

    def test_api_error_response_format(self, zerossl_api_key):
        """Test that API errors are properly formatted."""
        client = ZeroSSLAPIClient(zerossl_api_key)

        # Try to get a non-existent certificate
        with pytest.raises(ZeroSSLHTTPError) as exc_info:
            client.get_certificate("non_existent_cert_id_12345")

        error = exc_info.value
        # Should have meaningful error message
        assert len(str(error)) > 0

    def _validate_certificate_structure(self, cert_data):
        """Validate that certificate data has expected structure."""
        required_fields = ['id', 'status']
        for field in required_fields:
            assert field in cert_data, f"Missing required field: {field}"

        # Status should be one of expected values
        valid_statuses = ['draft', 'pending_validation', 'issued', 'cancelled', 'expired']
        assert cert_data['status'] in valid_statuses

        # ID should be a non-empty string
        assert isinstance(cert_data['id'], str)
        assert len(cert_data['id']) > 0

    def _should_skip_create_test(self):
        """Determine if we should skip certificate creation tests."""
        # You might implement logic here to check:
        # - Time of day (avoid peak hours)
        # - Number of certificates already created today
        # - API quota remaining
        return False

    def _generate_simple_csr(self, csr_path, domain):
        """Generate a valid CSR for testing."""
        # Skip if file already exists
        if csr_path.exists():
            return

        try:
            # Use the existing generate_csr utility function
            csr_content, private_key_content = generate_csr([domain])

            # Write CSR to file
            with open(csr_path, 'w') as f:
                f.write(csr_content)

            # Write private key to companion file
            key_path = csr_path.with_suffix('.key')
            with open(key_path, 'w') as f:
                f.write(private_key_content)

        except Exception as e:
            # If CSR generation fails, skip the test
            pytest.skip(f"Cannot generate CSR: {e}")


@pytest.mark.integration
@pytest.mark.live
class TestLiveAPIPerformance:
    """Test API performance characteristics."""

    def test_api_response_times(self, zerossl_api_key):
        """Test that API calls complete within reasonable time."""
        import time

        client = ZeroSSLAPIClient(zerossl_api_key)

        # Test list certificates performance
        start_time = time.time()
        response = client.list_certificates()
        elapsed = time.time() - start_time

        assert elapsed < 30, f"list_certificates took too long: {elapsed:.2f}s"
        print(f"list_certificates completed in {elapsed:.2f}s")

    def test_concurrent_api_calls(self, zerossl_api_key):
        """Test that multiple API calls can be made concurrently."""
        import threading
        import time

        client = ZeroSSLAPIClient(zerossl_api_key)
        results = []
        errors = []

        def make_api_call(call_id):
            try:
                start_time = time.time()
                response = client.list_certificates()
                elapsed = time.time() - start_time
                results.append({
                    'call_id': call_id,
                    'elapsed': elapsed,
                    'success': True
                })
            except Exception as e:
                errors.append({
                    'call_id': call_id,
                    'error': str(e)
                })

        # Make 3 concurrent calls (be conservative to avoid rate limits)
        threads = []
        for i in range(3):
            thread = threading.Thread(target=make_api_call, args=(i,))
            threads.append(thread)
            thread.start()
            time.sleep(0.5)  # Stagger calls slightly

        # Wait for all threads
        for thread in threads:
            thread.join(timeout=60)

        # Check results
        print(f"Concurrent API test results: {len(results)} successful, {len(errors)} errors")

        # Should have at least some successful calls
        assert len(results) > 0, "No successful concurrent API calls"

        # Print any errors for debugging
        for error in errors:
            print(f"API call {error['call_id']} failed: {error['error']}")
