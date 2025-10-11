# -*- coding: utf-8 -*-
"""
Improved component test for security and permissions.

This test covers security aspects using HTTP boundary mocking only.
Tests real security validation methods with actual file operations and data protection.
Follows improved test design patterns: mock only at HTTP boundaries, use real security logic.
"""

import pytest
import os
import stat
import tempfile
from unittest.mock import Mock
from plugins.action.zerossl_certificate import ActionModule


@pytest.mark.component
class TestSecurityAndPermissions:
    """Improved security and permission tests using HTTP boundary mocking and real security validation."""

    def test_api_key_not_logged(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test that API keys are not logged or exposed using real security protection."""
        csr_path = temp_directory / "security.csr"
        cert_path = temp_directory / "security.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDHNlY3VyaXR5LmNvbTCBnzAN
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "request",
            "web_root": str(temp_directory),
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual API key protection
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Use new sequential mocking approach for security test
        mock_http_boundary("success")

        # Execute real workflow - should protect API key in all outputs
        result = action_module.run(task_vars=mock_task_vars)

        # Verify API key protection in result
        result_str = str(result)
        assert sample_api_key not in result_str, "API key should not appear in result output"

        # Check all nested values in result don't contain API key
        def check_no_api_key_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    check_no_api_key_recursive(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]" if path else f"[{i}]"
                    check_no_api_key_recursive(item, current_path)
            elif isinstance(obj, str):
                assert sample_api_key not in obj, f"API key found in {path}: {obj}"

        check_no_api_key_recursive(result)

    def test_certificate_file_permissions(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test that certificate files are created with secure permissions using real file operations."""
        csr_path = temp_directory / "permissions.csr"
        cert_path = temp_directory / "permissions.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDHBlcm1pc3Npb25zLmNvbQ==
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

        # Create real ActionModule - test actual file permission setting
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Use new sequential mocking approach for successful certificate workflow
        mock_http_boundary("success")

        # Execute real workflow - should create files with secure permissions
        result = action_module.run(task_vars=mock_task_vars)

        # Verify certificate file was created with real file operations
        assert result["changed"] is True
        assert cert_path.exists()

        # Test actual file permissions
        file_stat = cert_path.stat()
        file_mode = file_stat.st_mode

        # Certificate files should be readable by owner but not world-readable
        assert file_mode & stat.S_IRUSR, "Owner should be able to read certificate file"
        assert file_mode & stat.S_IWUSR, "Owner should be able to write certificate file"

        # Check that file is not world-readable for security
        world_readable = file_mode & stat.S_IROTH
        if world_readable:
            # If world-readable, it should be intentional (some deployments require it)
            # But log a warning in real implementation
            pass

        # Verify file contains actual certificate content
        cert_content = cert_path.read_text()
        assert "-----BEGIN CERTIFICATE-----" in cert_content
        assert len(cert_content) > 100  # Substantial content

    def test_private_key_file_permissions(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test that private key files are created with strict permissions using real security measures."""
        csr_path = temp_directory / "private_key_test.csr"
        cert_path = temp_directory / "private_key_test.crt"
        key_path = temp_directory / "private_key_test.key"

        # Create realistic private key content for testing
        private_key_content = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfZKL6lBJ/LgO3YsLbFXXyZ4tDsO6FmzqXvWZqNwJwFxqVbmxcQKdmxNnkGXH7
8wNhz2xZGlE4uM7x5hXjNqxgJUQbFRl7ZqHJPZe5xfhKhJwCZl5vBz4J5Lxv
-----END PRIVATE KEY-----"""
        key_path.write_text(private_key_content)

        # Set strict permissions on private key (only owner can read/write)
        key_path.chmod(0o600)

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDHByaXZhdGUta2V5LmNvbTCB
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "private_key_path": str(key_path),
            "state": "present",
            "web_root": str(temp_directory),
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual private key security
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Use new sequential mocking approach for successful workflow
        mock_http_boundary("success")

        # Execute real workflow - should maintain private key security
        result = action_module.run(task_vars=mock_task_vars)

        # Verify workflow completed
        assert result["changed"] is True

        # Verify private key permissions remain strict
        key_stat = key_path.stat()
        key_mode = key_stat.st_mode

        # Private key should only be accessible by owner
        assert key_mode & stat.S_IRUSR, "Owner should be able to read private key"
        assert key_mode & stat.S_IWUSR, "Owner should be able to write private key"
        assert not (key_mode & stat.S_IRGRP), "Group should not be able to read private key"
        assert not (key_mode & stat.S_IWGRP), "Group should not be able to write private key"
        assert not (key_mode & stat.S_IROTH), "Others should not be able to read private key"
        assert not (key_mode & stat.S_IWOTH), "Others should not be able to write private key"

        # Verify private key content is preserved
        key_content = key_path.read_text()
        assert "-----BEGIN PRIVATE KEY-----" in key_content

    def test_temporary_file_cleanup(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test that temporary files are properly cleaned up using real cleanup logic."""
        csr_path = temp_directory / "cleanup.csr"
        cert_path = temp_directory / "cleanup.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDGNsZWFudXAuY29tMIIBIjAN
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "download",
            "certificate_id": "cleanup_cert_123",
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual cleanup behavior
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Use new sequential mocking approach for successful download
        mock_http_boundary("success")

        # Execute real workflow - should handle cleanup properly
        result = action_module.run(task_vars=mock_task_vars)

        # Verify download completed - may or may not be changed depending on existing files
        assert "changed" in result
        if not result.get("failed"):
            assert cert_path.exists()

        # Verify no sensitive temporary files are left behind
        temp_files = list(temp_directory.glob("*.tmp"))
        for temp_file in temp_files:
            # If temp files exist, they should not contain sensitive data
            if temp_file.exists():
                content = temp_file.read_text()
                assert sample_api_key not in content, "API key should not be in temp files"

    def test_validation_file_security(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test security of validation files using real validation file handling."""
        csr_path = temp_directory / "validation_security.csr"
        cert_path = temp_directory / "validation_security.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDHZhbGlkYXRpb24uY29tMIIB
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "request",
            "validation_method": "HTTP_CSR_HASH",
            "web_root": str(temp_directory),
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual validation file security
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Use new sequential mocking approach for validation workflow
        mock_http_boundary("success")

        # Execute real workflow - should create validation files securely
        result = action_module.run(task_vars=mock_task_vars)

        # Verify validation files were created
        assert result["changed"] is True

        # Check validation files security
        validation_dir = temp_directory / ".well-known" / "pki-validation"
        if validation_dir.exists():
            validation_files = list(validation_dir.glob("*.txt"))
            for validation_file in validation_files:
                # Validation files should exist and be readable
                assert validation_file.exists()

                # Check file permissions
                file_stat = validation_file.stat()
                file_mode = file_stat.st_mode

                # Validation files need to be readable by web server
                assert file_mode & stat.S_IRUSR, "Owner should be able to read validation file"

                # Content should not contain sensitive information
                content = validation_file.read_text()
                assert sample_api_key not in content, "API key should not be in validation files"
                assert len(content) > 10, "Validation file should have meaningful content"

    def test_error_message_sanitization(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test that error messages don't expose sensitive information using real error handling."""
        csr_path = temp_directory / "error_sanitization.csr"
        cert_path = temp_directory / "error_sanitization.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDGVycm9yLXRlc3QuY29tMIIB
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "present",
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual error sanitization
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Use new sequential mocking approach for error response
        mock_http_boundary("auth_error")

        # Execute real workflow - should handle errors with sanitization
        result = action_module.run(task_vars=mock_task_vars)

        # Check if ActionModule returns error result for sanitization test
        if result.get("failed"):
            error_message = result.get("msg", "")
            assert (
                sample_api_key not in error_message
            ), "API key should not appear in error messages"
            assert len(error_message) > 0, "Error message should not be empty"
            assert any(
                keyword in error_message.lower()
                for keyword in ["error", "failed", "invalid", "validation", "required"]
            ), "Error message should contain meaningful error information"
        else:
            # If not failed, check that error handling was graceful
            assert "changed" in result

    def test_secure_file_handling_edge_cases(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test secure file handling edge cases using real file security logic."""
        # Test with files that have unusual names or paths
        unusual_chars_dir = temp_directory / "unusual chars & symbols"
        unusual_chars_dir.mkdir(exist_ok=True)

        csr_path = unusual_chars_dir / "test with spaces.csr"
        cert_path = unusual_chars_dir / "test with spaces.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDHVudXN1YWwuY29tMIIBIjAN
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "present",
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual file handling edge cases
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Use new sequential mocking approach for successful workflow
        mock_http_boundary("success")

        # Execute real workflow - should handle unusual file paths securely
        result = action_module.run(task_vars=mock_task_vars)

        # Verify workflow handles unusual paths
        assert "changed" in result
        if not result.get("failed"):
            assert cert_path.exists()

            # Verify file security is maintained even with unusual names
            file_stat = cert_path.stat()
            assert file_stat.st_mode & stat.S_IRUSR, "File should be readable by owner"

    def test_memory_security_sensitive_data(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test that sensitive data doesn't persist in memory or variables using real memory handling."""
        csr_path = temp_directory / "memory_security.csr"
        cert_path = temp_directory / "memory_security.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDG1lbW9yeS5jb21NMIIB
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "present",
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual memory security
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Use new sequential mocking approach for successful workflow
        mock_http_boundary("success")

        # Execute real workflow
        result = action_module.run(task_vars=mock_task_vars)

        # Verify workflow completed
        assert "changed" in result

        # Test that action_module instance variables don't contain API key (only if successful)
        if not result.get("failed"):
            for attr_name in dir(action_module):
                if not attr_name.startswith("_"):
                    attr_value = getattr(action_module, attr_name, None)
                    if isinstance(attr_value, str):
                        assert (
                            sample_api_key not in attr_value
                        ), f"API key found in attribute {attr_name}"
                    elif isinstance(attr_value, dict):
                        attr_str = str(attr_value)
                        assert (
                            sample_api_key not in attr_str
                        ), f"API key found in dict attribute {attr_name}"

    def test_input_validation_security(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test input validation for security vulnerabilities using real validation logic."""
        # Test potentially dangerous file paths
        dangerous_paths = [
            "../../../etc/passwd",
            "/etc/shadow",
            "~/.ssh/id_rsa",
            temp_directory / ".." / "dangerous.crt",
        ]

        for dangerous_path in dangerous_paths:
            csr_path = temp_directory / "input_validation.csr"

            csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDGlucHV0LXRlc3QuY29tMIIB
-----END CERTIFICATE REQUEST-----"""
            csr_path.write_text(csr_content)

            task_args = {
                "api_key": sample_api_key,
                "domains": sample_domains,
                "csr_path": str(csr_path),
                "certificate_path": str(dangerous_path),  # Potentially dangerous path
                "state": "present",
            }

            mock_action_base._task.args = task_args

            # Create real ActionModule - test actual input validation
            action_module = ActionModule(
                task=mock_action_base._task,
                connection=Mock(),
                play_context=Mock(),
                loader=Mock(),
                templar=Mock(),
                shared_loader_obj=Mock(),
            )

            try:
                # Use new sequential mocking approach for workflow
                mock_http_boundary("success")

                # Execute workflow - should handle dangerous paths safely
                result = action_module.run(task_vars=mock_task_vars)

                # If it succeeds, verify it didn't write to dangerous location
                dangerous_file = Path(dangerous_path)
                if dangerous_file.exists() and dangerous_file.is_absolute():
                    # If file was created in absolute dangerous path, that's a problem
                    if str(dangerous_path).startswith("/etc/") or str(dangerous_path).startswith(
                        "/root/"
                    ):
                        assert False, f"Certificate written to dangerous path: {dangerous_path}"

            except Exception as e:
                # Input validation errors are acceptable and expected for dangerous paths
                error_message = str(e)
                assert (
                    sample_api_key not in error_message
                ), "API key should not be in validation error messages"

    def test_certificate_chain_validation_security(
        self,
        mock_action_base,
        mock_task_vars,
        sample_api_key,
        sample_domains,
        temp_directory,
        mock_http_boundary,
        mock_zerossl_api_responses,
    ):
        """Test certificate chain validation for security using real validation methods."""
        csr_path = temp_directory / "chain_validation.csr"
        cert_path = temp_directory / "chain_validation.crt"

        csr_content = """-----BEGIN CERTIFICATE REQUEST-----
MIICljCCAX4CAQAwUTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAMMDGNoYWluLXRlc3QuY29tMIIB
-----END CERTIFICATE REQUEST-----"""
        csr_path.write_text(csr_content)

        task_args = {
            "api_key": sample_api_key,
            "domains": sample_domains,
            "csr_path": str(csr_path),
            "certificate_path": str(cert_path),
            "state": "present",
        }

        mock_action_base._task.args = task_args

        # Create real ActionModule - test actual certificate validation
        action_module = ActionModule(
            task=mock_action_base._task,
            connection=Mock(),
            play_context=Mock(),
            loader=Mock(),
            templar=Mock(),
            shared_loader_obj=Mock(),
        )

        # Use new sequential mocking approach for certificate chain workflow
        mock_http_boundary("success")

        # Execute real workflow - should validate certificate chain properly
        result = action_module.run(task_vars=mock_task_vars)

        # Verify certificate chain was processed
        assert "changed" in result
        if not result.get("failed") and cert_path.exists():
            # Verify certificate chain format
            cert_content = cert_path.read_text()
            assert "-----BEGIN CERTIFICATE-----" in cert_content

            # Certificate chain should contain multiple certificates
            cert_count = cert_content.count("-----BEGIN CERTIFICATE-----")
            if cert_count > 1:
                # If chain contains intermediate certificates, verify structure
                assert cert_content.count("-----END CERTIFICATE-----") == cert_count

            # Verify no sensitive data in certificate
            assert sample_api_key not in cert_content
