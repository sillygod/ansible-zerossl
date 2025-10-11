# -*- coding: utf-8 -*-
"""
Mock Helper Functions for ZeroSSL Testing.

Utilities for creating mocks and test data for ZeroSSL plugin testing.
"""

import io
import json
import zipfile
from unittest.mock import Mock, MagicMock
import requests

from .zerossl_responses import (
    MOCK_CERTIFICATE_ZIP_FILES,
    RATE_LIMIT_HEADERS,
    RATE_LIMIT_EXCEEDED_HEADERS,
)


class MockResponse:
    """Mock HTTP response object."""

    def __init__(self, json_data=None, status_code=200, headers=None, content=None):
        self.json_data = json_data or {}
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content or b""
        self.text = json.dumps(json_data) if json_data else ""

    def json(self):
        if self.json_data is None:
            raise ValueError("No JSON object could be decoded")
        return self.json_data

    def raise_for_status(self):
        if 400 <= self.status_code < 600:
            raise requests.HTTPError(f"HTTP {self.status_code} Error")


class MockZeroSSLAPIClient:
    """Mock ZeroSSL API client for testing."""

    def __init__(self, api_key="test-api-key", fail_on=None, rate_limit_remaining=5000):
        self.api_key = api_key
        self.base_url = "https://api.zerossl.com"
        self.timeout = 30
        self.rate_limit_remaining = rate_limit_remaining
        self.fail_on = fail_on or []  # List of methods that should fail
        self.call_count = {}

    def _track_call(self, method_name):
        """Track method calls for testing."""
        self.call_count[method_name] = self.call_count.get(method_name, 0) + 1

    def _should_fail(self, method_name):
        """Check if method should fail for testing."""
        return method_name in self.fail_on

    def create_certificate(self, domains, csr, validity_days=90):
        """Mock certificate creation."""
        self._track_call("create_certificate")

        if self._should_fail("create_certificate"):
            from ansible.module_utils.zerossl.exceptions import ZeroSSLHTTPError

            raise ZeroSSLHTTPError("Mock certificate creation failure")

        from .zerossl_responses import create_certificate_response, create_validation_files_response

        cert_response = create_certificate_response(
            common_name=domains[0],
            additional_domains=",".join(domains[1:]) if len(domains) > 1 else "",
            days_valid=validity_days,
        )

        # Add validation data
        cert_response["validation"] = {"other_methods": create_validation_files_response(domains)}

        return cert_response

    def get_certificate(self, certificate_id):
        """Mock certificate status retrieval."""
        self._track_call("get_certificate")

        if self._should_fail("get_certificate"):
            from ansible.module_utils.zerossl.exceptions import ZeroSSLHTTPError

            raise ZeroSSLHTTPError("Mock certificate retrieval failure")

        from .zerossl_responses import CERTIFICATE_ISSUED_RESPONSE

        response = CERTIFICATE_ISSUED_RESPONSE.copy()
        response["id"] = certificate_id
        return response

    def list_certificates(self, status=None, page=1, limit=25):
        """Mock certificate listing."""
        self._track_call("list_certificates")

        if self._should_fail("list_certificates"):
            from ansible.module_utils.zerossl.exceptions import ZeroSSLHTTPError

            raise ZeroSSLHTTPError("Mock certificate listing failure")

        from .zerossl_responses import CERTIFICATE_LIST_RESPONSE

        return CERTIFICATE_LIST_RESPONSE

    def validate_certificate(self, certificate_id, validation_method):
        """Mock certificate validation."""
        self._track_call("validate_certificate")

        if self._should_fail("validate_certificate"):
            from ansible.module_utils.zerossl.exceptions import ZeroSSLValidationError

            raise ZeroSSLValidationError("Mock validation failure")

        from .zerossl_responses import VALIDATION_SUCCESS_RESPONSE

        response = VALIDATION_SUCCESS_RESPONSE.copy()
        response["certificate_id"] = certificate_id
        return response

    def download_certificate(self, certificate_id):
        """Mock certificate download."""
        self._track_call("download_certificate")

        if self._should_fail("download_certificate"):
            from ansible.module_utils.zerossl.exceptions import ZeroSSLHTTPError

            raise ZeroSSLHTTPError("Mock certificate download failure")

        # Create a mock ZIP file content
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for filename, content in MOCK_CERTIFICATE_ZIP_FILES.items():
                zip_file.writestr(filename, content)

        return zip_buffer.getvalue()

    def cancel_certificate(self, certificate_id):
        """Mock certificate cancellation."""
        self._track_call("cancel_certificate")

        if self._should_fail("cancel_certificate"):
            from ansible.module_utils.zerossl.exceptions import ZeroSSLHTTPError

            raise ZeroSSLHTTPError("Mock certificate cancellation failure")

        return {"success": True, "certificate_id": certificate_id, "status": "cancelled"}

    def get_verification_details(self, certificate_id):
        """Mock verification details retrieval."""
        self._track_call("get_verification_details")

        if self._should_fail("get_verification_details"):
            from ansible.module_utils.zerossl.exceptions import ZeroSSLHTTPError

            raise ZeroSSLHTTPError("Mock verification details failure")

        from .zerossl_responses import create_validation_files_response

        return {"validation": {"other_methods": create_validation_files_response(["example.com"])}}


class MockCertificateManager:
    """Mock Certificate Manager for testing."""

    def __init__(self, api_key="test-api-key", api_client=None, enable_caching=False):
        self.api_key = api_key
        self.api_client = api_client or MockZeroSSLAPIClient(api_key)
        self.enable_caching = enable_caching
        self.call_count = {}

    def _track_call(self, method_name):
        """Track method calls for testing."""
        self.call_count[method_name] = self.call_count.get(method_name, 0) + 1

    def create_certificate(self, domains, csr, validation_method, validity_days=90):
        """Mock certificate creation with validation info."""
        self._track_call("create_certificate")

        from .zerossl_responses import create_dns_records_response

        cert_response = self.api_client.create_certificate(domains, csr, validity_days)

        # Prepare validation files or DNS records
        validation_files = []
        dns_records = []

        if validation_method == "HTTP_CSR_HASH":
            validation_data = cert_response.get("validation", {}).get("other_methods", {})
            for domain, data in validation_data.items():
                validation_files.append(
                    {
                        "domain": domain,
                        "url_path": data["file_validation_url_https"].split("/")[-1],
                        "content": data["file_validation_content"][0],
                    }
                )
        elif validation_method == "DNS_CSR_HASH":
            dns_records = create_dns_records_response(domains)

        return {
            "certificate_id": cert_response["id"],
            "status": cert_response["status"],
            "domains": domains,
            "validation_method": validation_method,
            "validation_files": validation_files,
            "dns_records": dns_records,
            "created": True,
            "changed": True,
        }

    def get_certificate_status(self, certificate_id):
        """Mock certificate status retrieval."""
        self._track_call("get_certificate_status")

        cert_data = self.api_client.get_certificate(certificate_id)
        return {
            "certificate_id": certificate_id,
            "status": cert_data["status"],
            "expires": cert_data.get("expires"),
            "common_name": cert_data.get("common_name"),
            "additional_domains": cert_data.get("additional_domains", ""),
            "created": cert_data.get("created"),
            "validation_completed": cert_data.get("validation_completed", False),
        }

    def find_certificate_for_domains(self, domains):
        """Mock certificate search by domains."""
        self._track_call("find_certificate_for_domains")

        # For testing, return a mock certificate ID if domains match
        if "example.com" in domains:
            return "cert-123456789"
        return None

    def needs_renewal(self, domains, threshold_days=30):
        """Mock renewal check."""
        self._track_call("needs_renewal")

        # For testing, assume certificate needs renewal if it contains 'expired'
        return any("expired" in domain for domain in domains)

    def validate_certificate(self, certificate_id, validation_method):
        """Mock certificate validation."""
        self._track_call("validate_certificate")

        result = self.api_client.validate_certificate(certificate_id, validation_method)
        return {
            "certificate_id": certificate_id,
            "validation_method": validation_method,
            "success": result.get("success", False),
            "validation_completed": result.get("validation_completed", False),
            "changed": True,
        }

    def download_certificate(self, certificate_id):
        """Mock certificate download and processing."""
        self._track_call("download_certificate")

        zip_content = self.api_client.download_certificate(certificate_id)

        # Process the ZIP content
        zip_buffer = io.BytesIO(zip_content)
        bundle_data = {"certificate": "", "private_key": "", "ca_bundle": "", "full_chain": ""}

        with zipfile.ZipFile(zip_buffer, "r") as zip_file:
            for file_info in zip_file.filelist:
                file_content = zip_file.read(file_info.filename).decode("utf-8")

                if file_info.filename == "certificate.crt":
                    bundle_data["certificate"] = file_content
                elif file_info.filename == "ca_bundle.crt":
                    bundle_data["ca_bundle"] = file_content
                elif file_info.filename == "private.key":
                    bundle_data["private_key"] = file_content

        # Create full chain
        if bundle_data["certificate"] and bundle_data["ca_bundle"]:
            bundle_data["full_chain"] = (
                bundle_data["certificate"].strip() + "\n" + bundle_data["ca_bundle"].strip()
            )

        return bundle_data


class MockValidationHandler:
    """Mock Validation Handler for testing."""

    def __init__(self):
        self.call_count = {}

    def _track_call(self, method_name):
        """Track method calls for testing."""
        self.call_count[method_name] = self.call_count.get(method_name, 0) + 1

    def prepare_http_validation(self, validation_data):
        """Mock HTTP validation file preparation."""
        self._track_call("prepare_http_validation")

        validation_files = []
        for domain, data in validation_data.items():
            validation_files.append(
                {
                    "domain": domain,
                    "url_path": data["file_validation_url_https"].split("/")[-1],
                    "content": data["file_validation_content"][0],
                    "file_path": f"/.well-known/pki-validation/{data['file_validation_url_https'].split('/')[-1]}",
                }
            )

        return validation_files

    def prepare_dns_validation(self, validation_data):
        """Mock DNS validation record preparation."""
        self._track_call("prepare_dns_validation")

        from .zerossl_responses import create_dns_records_response

        domains = list(validation_data.keys())
        return create_dns_records_response(domains)

    def place_validation_files(self, validation_files, web_root):
        """Mock validation file placement."""
        self._track_call("place_validation_files")

        return {"success": True, "files_placed": len(validation_files), "web_root": web_root}


def create_mock_session_with_responses(responses):
    """Create a mock requests session with predefined responses."""
    session = Mock()
    session.headers = {}

    def side_effect(*args, **kwargs):
        url = args[0] if args else kwargs.get("url", "")

        # Determine response based on URL patterns
        if "/certificates" in url and "download" in url:
            # Certificate download
            response = MockResponse(
                content=create_mock_certificate_zip(), status_code=200, headers=RATE_LIMIT_HEADERS
            )
        elif "/certificates" in url and url.endswith("/certificates"):
            # Certificate list
            response = MockResponse(
                json_data=responses.get("list", {}), status_code=200, headers=RATE_LIMIT_HEADERS
            )
        elif "/certificates/" in url and "/challenges" in url:
            # Certificate validation
            response = MockResponse(
                json_data=responses.get("validate", {}), status_code=200, headers=RATE_LIMIT_HEADERS
            )
        elif "/certificates/" in url:
            # Individual certificate
            response = MockResponse(
                json_data=responses.get("get", {}), status_code=200, headers=RATE_LIMIT_HEADERS
            )
        else:
            # Default response
            response = MockResponse(
                json_data=responses.get("default", {}), status_code=200, headers=RATE_LIMIT_HEADERS
            )

        return response

    session.get.side_effect = side_effect
    session.post.side_effect = side_effect

    return session


def create_mock_certificate_zip():
    """Create a mock certificate ZIP file for testing."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for filename, content in MOCK_CERTIFICATE_ZIP_FILES.items():
            zip_file.writestr(filename, content)

    return zip_buffer.getvalue()


def create_test_file_structure(tmp_path):
    """Create a temporary test file structure."""
    test_dirs = {
        "certs": tmp_path / "etc" / "ssl" / "certs",
        "private": tmp_path / "etc" / "ssl" / "private",
        "web_root": tmp_path / "var" / "www" / "html",
        "validation": tmp_path / "var" / "www" / "html" / ".well-known" / "pki-validation",
    }

    for directory in test_dirs.values():
        directory.mkdir(parents=True, exist_ok=True)

    return test_dirs


def assert_file_content(file_path, expected_content):
    """Assert that file contains expected content."""
    with open(file_path, "r", encoding="utf-8") as f:
        actual_content = f.read().strip()
    assert actual_content == expected_content.strip(), f"File content mismatch in {file_path}"


def assert_file_permissions(file_path, expected_mode):
    """Assert that file has expected permissions."""
    import stat

    actual_mode = stat.filemode(file_path.stat().st_mode)[-3:]
    expected_str = oct(expected_mode)[-3:]
    assert (
        actual_mode == expected_str
    ), f"File permissions mismatch: expected {expected_str}, got {actual_mode}"
