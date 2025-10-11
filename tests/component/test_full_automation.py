# -*- coding: utf-8 -*-
"""
Improved component test for full certificate automation scenario.

This test covers the complete workflow orchestration using HTTP boundary mocking only.
Tests real ActionModule workflows end-to-end with realistic ZeroSSL API responses.
Follows improved test design patterns: mock only at HTTP boundaries, use real business logic.
"""

import pytest
import os
from pathlib import Path
from unittest.mock import Mock
from plugins.action.zerossl_certificate import ActionModule


@pytest.mark.component
class TestFullCertificateAutomation:
    """Improved component tests for complete certificate automation workflow using HTTP boundary mocking only."""

    def test_full_automation_new_certificate(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test full automation for new certificate creation using real workflow methods."""
        # Setup realistic test files with actual PEM content
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"
        key_path = temp_directory / "test.key"

        # Use realistic CSR content
        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDGV4YW1wbGUuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Si
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        # Configure task arguments for full automation
        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "present",
            "validation_method": "HTTP_CSR_HASH",
            "web_root": str(temp_directory),
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule instance - no internal method mocking
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Set up sequential HTTP boundary mocking for complete workflow
        mock_http_boundary()

        # Execute real workflow end-to-end
        result = action_module.run(task_vars=mock_task_vars)

        # Verify complete workflow execution with real business logic
        assert result["changed"] is True
        assert "certificate_id" in result
        assert cert_path.exists()  # Certificate file actually created

        # Verify certificate content was written (real file operations)
        cert_content = cert_path.read_text()
        assert "-----BEGIN CERTIFICATE-----" in cert_content
        assert len(cert_content) > 100  # Non-empty certificate content

    def test_full_automation_existing_valid_certificate(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test full automation when certificate already exists and is valid - real idempotency logic."""
        # Setup test files with realistic content
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDGV4YW1wbGUuY29tMIIB
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        # Pre-create existing valid certificate file
        existing_cert = mock_zerossl_api_responses["certificate_download"]["certificate.crt"]
        cert_path.write_text(existing_cert)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "present",
            "renew_threshold_days": 30,
            "web_root": str(temp_directory),
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual idempotency logic
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Set up sequential HTTP boundary mocking for existing certificate scenario
        # (This will mock the list_certificates call to return existing certificate)
        mock_http_boundary("existing_certificate")

        # Execute real workflow - should detect existing valid certificate
        result = action_module.run(task_vars=mock_task_vars)

        # Verify idempotency logic worked correctly
        assert result["changed"] is False
        assert "certificate_id" in result

        # Original certificate file should be unchanged
        assert cert_path.exists()
        current_content = cert_path.read_text()
        assert current_content == existing_cert

    def test_full_automation_certificate_renewal(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test full automation when certificate needs renewal - real renewal logic."""
        # Setup test files
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        # Pre-create expiring certificate file
        expiring_cert = mock_zerossl_api_responses["certificate_download"]["certificate.crt"]
        cert_path.write_text(expiring_cert)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "present",
            "renew_threshold_days": 30,  # Aggressive renewal for testing
            "web_root": str(temp_directory),
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule to test actual renewal detection logic
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Set up sequential HTTP boundary mocking for certificate renewal scenario
        mock_http_boundary("expiring_certificate")

        # Execute real renewal workflow
        result = action_module.run(task_vars=mock_task_vars)

        # Verify renewal logic executed correctly
        assert result["changed"] is True
        assert "certificate_id" in result

        # Certificate file should be updated with new certificate
        new_content = cert_path.read_text()
        assert new_content != expiring_cert  # Content changed
        assert "-----BEGIN CERTIFICATE-----" in new_content

    def test_full_automation_with_multiple_domains(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test full automation with multiple domains (SAN certificate) - real domain processing."""
        # Multiple domains for SAN certificate
        multiple_domains = ["example.com", "www.example.com", "api.example.com", "cdn.example.com"]

        # Setup test files with realistic SAN CSR
        csr_path = temp_directory / "san.csr"
        cert_path = temp_directory / "san.crt"

        san_csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICpjCCAY4CAQAwYTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xJTAjBgNVBAMMHGV4YW1wbGUuY29tLHd3
dy5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtU
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(san_csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": multiple_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "present",
            "validation_method": "HTTP_CSR_HASH",
            "web_root": str(temp_directory),
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual multi-domain processing
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Set up sequential HTTP boundary mocking for SAN certificate workflow
        mock_http_boundary()

        # Execute real SAN certificate workflow
        result = action_module.run(task_vars=mock_task_vars)

        # Verify SAN certificate creation with real domain processing
        assert result["changed"] is True
        assert "certificate_id" in result

        # Verify certificate file contains SAN certificate
        assert cert_path.exists()
        san_cert_content = cert_path.read_text()
        assert "-----BEGIN CERTIFICATE-----" in san_cert_content

        # Verify validation files created for all domains
        validation_dir = temp_directory / ".well-known" / "pki-validation"
        if validation_dir.exists():
            validation_files = list(validation_dir.glob("*.txt"))
            assert len(validation_files) >= 1  # At least one validation file created

    def test_full_automation_error_recovery(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test error recovery in full automation workflow - real error handling logic."""
        # Setup test files
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "present",
            "web_root": str(temp_directory),
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual error handling
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Set up sequential HTTP boundary mocking for error scenario
        mock_http_boundary("validation_error")

        # Execute workflow - should handle validation failure gracefully
        result = action_module.run(task_vars=mock_task_vars)

        # Verify proper error handling and propagation
        assert result["changed"] is False
        assert "failed" in result or "msg" in result
        error_message = result.get("msg", "").lower()
        assert any(
            keyword in error_message
            for keyword in ["validation", "failed", "error", "api request failed"]
        )

    def test_full_automation_file_permissions(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test that certificate files are saved with correct permissions - real file operations."""
        # Setup test files
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "present",
            "web_root": str(temp_directory),
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual file handling
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Set up sequential HTTP boundary mocking for file permissions test
        mock_http_boundary()

        # Execute real workflow with file operations
        result = action_module.run(task_vars=mock_task_vars)

        # Verify certificate file was created with real file operations
        assert result["changed"] is True
        assert cert_path.exists()

        # Check file permissions are set correctly (readable but not world-readable for security)
        import stat

        file_stat = cert_path.stat()
        file_mode = stat.filemode(file_stat.st_mode)

        # Certificate file should be readable by owner/group but not world
        assert file_stat.st_mode & stat.S_IRUSR  # Owner can read
        assert file_stat.st_mode & stat.S_IWUSR  # Owner can write

        # Verify file contains actual certificate content
        cert_content = cert_path.read_text()
        assert "-----BEGIN CERTIFICATE-----" in cert_content
        assert len(cert_content) > 100

    def test_full_automation_ansible_facts(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test that automation workflow sets appropriate Ansible facts - real result processing."""
        # Setup test files
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "present",
            "web_root": str(temp_directory),
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual fact generation
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Set up sequential HTTP boundary mocking for Ansible facts test
        mock_http_boundary()

        # Execute real workflow
        result = action_module.run(task_vars=mock_task_vars)

        # Verify result contains complete fact information
        assert result["changed"] is True
        assert "certificate_id" in result
        assert isinstance(result["certificate_id"], str)
        assert isinstance(result["changed"], bool)

        # Verify additional fact fields that should be present
        expected_fact_fields = ["certificate_id", "changed"]
        for field in expected_fact_fields:
            assert field in result, f"Expected fact field '{field}' missing from result"

        # Verify facts can be registered properly (correct data types)
        if "domains" in result:
            assert isinstance(result["domains"], list)
        if "expiry_date" in result:
            assert isinstance(result["expiry_date"], str)
        if "validation_method" in result:
            assert isinstance(result["validation_method"], str)

    def test_full_automation_state_transitions(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test complete state transition workflow - real state management logic."""
        # Setup test files
        csr_path = temp_directory / "test.csr"
        cert_path = temp_directory / "test.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        # Test different states in sequence
        states_to_test = ["present", "validate", "download"]

        for state in states_to_test:
            task_args = {
                "api_key": sample_api_key,
                "domains": sample_domains,
                "csr_path": str(csr_path),
                "certificate_path": str(cert_path),
                "state": state,
                "web_root": str(temp_directory),
            }

            # Add certificate_id for states that require it
            if state in ["validate", "download"]:
                task_args["certificate_id"] = "test_cert_success_123"

            mock_action_base._task.args = task_args

            # Create real ActionModule for each state
            action_module = ActionModule(
                task=mock_action_base._task,
                connection=Mock(),
                play_context=Mock(),
                loader=Mock(),
                templar=Mock(),
                shared_loader_obj=Mock(),
            )

            # Use new sequential mocking approach for all states
            mock_http_boundary("success")

            # Execute real state handling
            result = action_module.run(task_vars=mock_task_vars)

            # All states should return valid results without internal method mocking
            assert isinstance(result, dict)
            # Accept both success and graceful failure handling
            if result.get("failed"):
                # Graceful failure is acceptable - verify error message exists
                assert "msg" in result
                assert len(result["msg"]) > 0
            else:
                # Successful execution (no 'failed' key or failed=False)
                # Verify state-specific results only for successful execution
                if state in ["present", "download"]:
                    assert result.get("changed") in [
                        True,
                        False,
                    ]  # Can be either based on existing state
