# -*- coding: utf-8 -*-
"""
Unit tests for ZeroSSL Models - Improved Design.

These tests verify data model functionality using real business logic
without mocking internal methods, only mocking at HTTP boundary when needed.

Test Design Principles:
- Exercise real Model constructors and methods
- Use realistic data structures and values
- Test actual method signatures and business logic
- Achieve comprehensive coverage through real execution
- No internal method mocking - only external dependencies when required
"""

import pytest
import tempfile
import os
from datetime import datetime, timedelta
from pathlib import Path

from plugins.module_utils.zerossl.models import (
    CertificateStatus,
    ValidationMethod,
    ValidationStatus,
    OperationState,
    Certificate,
    DomainValidation,
    APICredentials,
    CertificateBundle,
)


@pytest.mark.unit
class TestEnumerationsReal:
    """Test all enumeration classes with real values."""

    def test_certificate_status_enumeration_real_values(self):
        """Test CertificateStatus enumeration with actual ZeroSSL API values."""
        # Test that enumeration values match real ZeroSSL API responses
        assert CertificateStatus.DRAFT.value == "draft"
        assert CertificateStatus.PENDING_VALIDATION.value == "pending_validation"
        assert CertificateStatus.ISSUED.value == "issued"
        assert CertificateStatus.EXPIRED.value == "expired"
        assert CertificateStatus.CANCELED.value == "canceled"

        # Test enumeration can be created from string values
        assert CertificateStatus("draft") == CertificateStatus.DRAFT
        assert CertificateStatus("issued") == CertificateStatus.ISSUED

    def test_validation_method_enumeration_real_values(self):
        """Test ValidationMethod enumeration with actual ZeroSSL API values."""
        # Test that enumeration values match real ZeroSSL API formats
        assert ValidationMethod.HTTP_01.value == "HTTP_CSR_HASH"
        assert ValidationMethod.DNS_01.value == "DNS_CSR_HASH"

        # Test enumeration can be created from string values
        assert ValidationMethod("HTTP_CSR_HASH") == ValidationMethod.HTTP_01
        assert ValidationMethod("DNS_CSR_HASH") == ValidationMethod.DNS_01

    def test_validation_status_enumeration_real_values(self):
        """Test ValidationStatus enumeration with real domain validation states."""
        assert ValidationStatus.PENDING.value == "pending"
        assert ValidationStatus.IN_PROGRESS.value == "in_progress"
        assert ValidationStatus.VALID.value == "valid"
        assert ValidationStatus.INVALID.value == "invalid"

    def test_operation_state_enumeration_real_values(self):
        """Test OperationState enumeration with real plugin operation states."""
        assert OperationState.PRESENT.value == "present"
        assert OperationState.REQUEST.value == "request"
        assert OperationState.VALIDATE.value == "validate"
        assert OperationState.DOWNLOAD.value == "download"
        assert OperationState.ABSENT.value == "absent"
        assert OperationState.CHECK_RENEWAL.value == "check_renew_or_create"


@pytest.mark.unit
class TestCertificateReal:
    """Test Certificate model with real business logic."""

    @pytest.fixture
    def mock_http_boundary(self, mocker):
        """Mock HTTP boundary for external API calls."""
        return mocker.patch("requests.Session")

    @pytest.fixture
    def sample_certificate_data(self):
        """Create realistic certificate data for testing."""
        return {
            "id": "zerossl-cert-12345",
            "domains": ["example.com", "www.example.com"],
            "status": CertificateStatus.ISSUED,
            "created_at": datetime(2023, 1, 1, 12, 0, 0),
            "expires_at": datetime(2023, 4, 1, 12, 0, 0),
            "validation_method": ValidationMethod.HTTP_01,
            "certificate_path": "/etc/ssl/certs/example.com.pem",
        }

    def test_certificate_real_initialization(self, sample_certificate_data):
        """
        Test Certificate initialization with real business logic.

        This test exercises the real Certificate constructor and validates
        proper initialization without mocking any internal methods.
        """
        cert = Certificate(**sample_certificate_data)

        # Verify real constructor behavior
        assert cert.id == "zerossl-cert-12345"
        assert cert.domains == ["example.com", "www.example.com"]
        assert cert.common_name == "example.com"  # Real logic: first domain
        assert cert.status == CertificateStatus.ISSUED
        assert cert.created_at == sample_certificate_data["created_at"]
        assert cert.expires_at == sample_certificate_data["expires_at"]
        assert cert.validation_method == ValidationMethod.HTTP_01
        assert cert.certificate_path == "/etc/ssl/certs/example.com.pem"

    def test_certificate_domain_validation_real_logic(self):
        """
        Test Certificate domain validation with real validation logic.

        This exercises the real _validate_domains static method without mocking.
        """
        # Test valid domains with real validation
        valid_domains = ["example.com", "www.example.com", "api.example.org"]
        result = Certificate._validate_domains(valid_domains)
        assert result == valid_domains

        # Test wildcard domain validation
        wildcard_domains = ["*.example.com"]
        result = Certificate._validate_domains(wildcard_domains)
        assert result == wildcard_domains

        # Test real error conditions
        with pytest.raises(ValueError) as exc_info:
            Certificate._validate_domains([])
        assert "At least one domain is required" in str(exc_info.value)

        with pytest.raises(ValueError) as exc_info:
            Certificate._validate_domains(["invalid..domain.com"])
        assert "Invalid domain format" in str(exc_info.value)

    def test_certificate_business_logic_methods(self, sample_certificate_data):
        """
        Test Certificate business logic methods with real implementation.

        This exercises real certificate status and expiry logic methods.
        """
        # Test is_valid with issued certificate
        cert = Certificate(**sample_certificate_data)
        assert cert.is_valid() is True

        # Test is_valid with draft certificate
        draft_data = sample_certificate_data.copy()
        draft_data["status"] = CertificateStatus.DRAFT
        draft_cert = Certificate(**draft_data)
        assert draft_cert.is_valid() is False

        # Test expiry logic with real datetime calculations
        current_time = datetime.utcnow()
        expired_data = sample_certificate_data.copy()
        expired_data["expires_at"] = current_time - timedelta(days=1)
        expired_cert = Certificate(**expired_data)
        assert expired_cert.is_expired() is True

        # Test future expiry
        future_data = sample_certificate_data.copy()
        future_data["expires_at"] = current_time + timedelta(days=30)
        future_cert = Certificate(**future_data)
        assert future_cert.is_expired() is False

    def test_certificate_renewal_logic_real_calculations(self, sample_certificate_data):
        """
        Test Certificate renewal logic with real date calculations.

        This exercises real needs_renewal and days_until_expiry methods
        with actual datetime arithmetic.
        """
        current_time = datetime.utcnow()

        # Test certificate expiring in 15 days
        renewal_data = sample_certificate_data.copy()
        renewal_data["expires_at"] = current_time + timedelta(days=15)
        renewal_cert = Certificate(**renewal_data)

        # Real calculation: expires in 15 days, threshold 30 days
        assert renewal_cert.needs_renewal(threshold_days=30) is True
        assert renewal_cert.needs_renewal(threshold_days=10) is False

        days_until = renewal_cert.days_until_expiry()
        assert 14 <= days_until <= 15  # Account for timing differences

    def test_certificate_to_dict_real_serialization(self, sample_certificate_data):
        """
        Test Certificate to_dict with real serialization logic.

        This exercises the real to_dict method without mocking any
        internal calculation methods.
        """
        current_time = datetime.utcnow()
        future_data = sample_certificate_data.copy()
        future_data["expires_at"] = current_time + timedelta(days=30)
        cert = Certificate(**future_data)

        result = cert.to_dict()

        # Verify real serialization output
        assert result["id"] == "zerossl-cert-12345"
        assert result["domains"] == ["example.com", "www.example.com"]
        assert result["common_name"] == "example.com"
        assert result["status"] == "issued"  # Enum value serialized
        assert result["validation_method"] == "HTTP_CSR_HASH"
        assert result["certificate_path"] == "/etc/ssl/certs/example.com.pem"
        assert result["is_valid"] is True  # Real method call
        assert result["is_expired"] is False  # Real method call
        assert isinstance(result["days_until_expiry"], int)  # Real calculation

    def test_certificate_from_zerossl_response_real_parsing(self):
        """
        Test Certificate.from_zerossl_response with real API response parsing.

        This exercises the real class method that parses actual ZeroSSL
        API response data without mocking the parsing logic.
        """
        # Realistic ZeroSSL API response
        api_response = {
            "id": "zerossl-api-12345",
            "common_name": "example.com",
            "additional_domains": "www.example.com, api.example.com, blog.example.com",
            "status": "issued",
            "created": "2023-01-01 12:00:00",
            "expires": "2023-04-01 12:00:00",
        }

        cert = Certificate.from_zerossl_response(api_response)

        # Verify real parsing logic
        assert cert.id == "zerossl-api-12345"
        assert cert.common_name == "example.com"
        assert "example.com" in cert.domains
        assert "www.example.com" in cert.domains
        assert "api.example.com" in cert.domains
        assert "blog.example.com" in cert.domains
        assert cert.status == CertificateStatus.ISSUED
        assert cert.validation_method == ValidationMethod.HTTP_01  # Default

    def test_certificate_from_zerossl_response_edge_cases_real_logic(self):
        """
        Test Certificate.from_zerossl_response edge cases with real parsing.

        This exercises real edge case handling in the parsing logic.
        """
        # Response with empty additional_domains
        response_empty_additional = {
            "id": "cert-123",
            "common_name": "single.example.com",
            "additional_domains": "",
            "status": "pending_validation",
            "created": "2023-01-01 00:00:00",
            "expires": "2023-04-01 00:00:00",
        }

        cert = Certificate.from_zerossl_response(response_empty_additional)
        assert cert.domains == ["single.example.com"]
        assert cert.status == CertificateStatus.PENDING_VALIDATION

        # Response without additional_domains field
        response_no_additional = {
            "id": "cert-456",
            "common_name": "simple.example.com",
            "status": "draft",
            "created": "2023-02-01 15:30:00",
            "expires": "2023-05-01 15:30:00",
        }

        cert = Certificate.from_zerossl_response(response_no_additional)
        assert cert.domains == ["simple.example.com"]


@pytest.mark.unit
class TestDomainValidationReal:
    """Test DomainValidation model with real business logic."""

    def test_domain_validation_http_real_initialization(self):
        """
        Test DomainValidation HTTP-01 initialization with real validation logic.

        This exercises the real constructor and validation without mocking.
        """
        validation = DomainValidation(
            domain="example.com",
            method=ValidationMethod.HTTP_01,
            challenge_token="abc123token456",
            challenge_url="http://example.com/.well-known/acme-challenge/abc123token456",
        )

        # Verify real initialization
        assert validation.domain == "example.com"
        assert validation.method == ValidationMethod.HTTP_01
        assert validation.challenge_token == "abc123token456"
        assert (
            validation.challenge_url
            == "http://example.com/.well-known/acme-challenge/abc123token456"
        )
        assert validation.status == ValidationStatus.PENDING  # Default
        assert validation.validated_at is None

    def test_domain_validation_dns_real_initialization(self):
        """
        Test DomainValidation DNS-01 initialization with real validation logic.

        This exercises real constructor validation for DNS validation method.
        """
        validation = DomainValidation(
            domain="example.com",
            method=ValidationMethod.DNS_01,
            challenge_token="dns-token-789",
            dns_record="_acme-challenge.example.com CNAME xyz123.zerossl.com",
        )

        assert validation.method == ValidationMethod.DNS_01
        assert validation.dns_record == "_acme-challenge.example.com CNAME xyz123.zerossl.com"
        assert validation.challenge_url is None

    def test_domain_validation_real_validation_logic(self):
        """
        Test DomainValidation internal validation with real logic.

        This exercises the real _validate method without mocking.
        """
        # Test HTTP validation missing URL
        with pytest.raises(ValueError) as exc_info:
            DomainValidation(
                domain="example.com",
                method=ValidationMethod.HTTP_01,
                challenge_token="token",
                # Missing challenge_url
            )
        assert "Challenge URL is required for HTTP-01 validation" in str(exc_info.value)

        # Test DNS validation missing record
        with pytest.raises(ValueError) as exc_info:
            DomainValidation(
                domain="example.com",
                method=ValidationMethod.DNS_01,
                challenge_token="token",
                # Missing dns_record
            )
        assert "DNS record is required for DNS-01 validation" in str(exc_info.value)

        # Test missing domain
        with pytest.raises(ValueError) as exc_info:
            DomainValidation(
                domain="",
                method=ValidationMethod.HTTP_01,
                challenge_token="token",
                challenge_url="http://example.com/token",
            )
        assert "Domain is required" in str(exc_info.value)

    def test_domain_validation_business_logic_methods(self):
        """
        Test DomainValidation business logic methods with real implementation.

        This exercises real is_complete and mark_validated methods.
        """
        validation = DomainValidation(
            domain="example.com",
            method=ValidationMethod.HTTP_01,
            challenge_token="token",
            challenge_url="http://example.com/token",
        )

        # Test initial state
        assert validation.is_complete() is False

        # Test mark_validated real logic
        before_time = datetime.utcnow()
        validation.mark_validated()
        after_time = datetime.utcnow()

        assert validation.status == ValidationStatus.VALID
        assert before_time <= validation.validated_at <= after_time
        assert validation.is_complete() is True

    def test_domain_validation_to_dict_real_serialization(self):
        """
        Test DomainValidation to_dict with real serialization logic.

        This exercises real serialization without mocking any methods.
        """
        validated_time = datetime.utcnow()
        validation = DomainValidation(
            domain="test.example.com",
            method=ValidationMethod.DNS_01,
            challenge_token="dns-token",
            dns_record="_acme-challenge.test.example.com CNAME validation.zerossl.com",
            status=ValidationStatus.VALID,
            validated_at=validated_time,
        )

        result = validation.to_dict()

        # Verify real serialization
        assert result["domain"] == "test.example.com"
        assert result["method"] == "DNS_CSR_HASH"
        assert result["challenge_token"] == "dns-token"
        assert (
            result["dns_record"] == "_acme-challenge.test.example.com CNAME validation.zerossl.com"
        )
        assert result["status"] == "valid"
        assert result["validated_at"] == validated_time.isoformat()
        assert result["is_complete"] is True  # Real method call


@pytest.mark.unit
class TestAPICredentialsReal:
    """Test APICredentials model with real business logic."""

    def test_api_credentials_real_initialization(self):
        """
        Test APICredentials initialization with real validation logic.

        This exercises the real constructor and validation without mocking.
        """
        reset_time = datetime.utcnow() + timedelta(hours=1)
        credentials = APICredentials(
            api_key="real-zerossl-api-key-1234567890123456789",
            rate_limit_remaining=4500,
            rate_limit_reset=reset_time,
        )

        # Verify real initialization
        assert credentials.api_key == "real-zerossl-api-key-1234567890123456789"
        assert credentials.rate_limit_remaining == 4500
        assert credentials.rate_limit_reset == reset_time

    def test_api_credentials_default_values_real_logic(self):
        """
        Test APICredentials default values with real initialization logic.

        This exercises real default value assignment.
        """
        credentials = APICredentials(api_key="valid-api-key-1234567890123456")

        assert credentials.rate_limit_remaining == 5000  # Real default
        assert isinstance(credentials.rate_limit_reset, datetime)  # Real default

    def test_api_credentials_validation_real_logic(self):
        """
        Test APICredentials validation with real validation logic.

        This exercises the real _validate_api_key static method.
        """
        # Test minimum valid length
        min_valid_key = "a" * 20
        credentials = APICredentials(api_key=min_valid_key)
        assert credentials.api_key == min_valid_key

        # Test real validation errors
        with pytest.raises(ValueError) as exc_info:
            APICredentials(api_key="")
        assert "API key is required" in str(exc_info.value)

        with pytest.raises(ValueError) as exc_info:
            APICredentials(api_key="too-short")
        assert "API key appears to be invalid (too short)" in str(exc_info.value)

    def test_api_credentials_rate_limit_logic_real_methods(self):
        """
        Test APICredentials rate limit logic with real business methods.

        This exercises real is_rate_limited and update_rate_limit methods.
        """
        credentials = APICredentials(
            api_key="test-api-key-1234567890123456", rate_limit_remaining=100
        )

        # Test real rate limit checking
        assert credentials.is_rate_limited() is False

        # Test rate limit exhaustion
        credentials.rate_limit_remaining = 0
        assert credentials.is_rate_limited() is True

        # Test real rate limit update
        new_reset_time = datetime.utcnow() + timedelta(hours=2)
        credentials.update_rate_limit(remaining=3000, reset_time=new_reset_time)

        assert credentials.rate_limit_remaining == 3000
        assert credentials.rate_limit_reset == new_reset_time

    def test_api_credentials_to_dict_real_security_logic(self):
        """
        Test APICredentials to_dict with real security logic.

        This exercises real serialization that excludes sensitive data.
        """
        credentials = APICredentials(
            api_key="sensitive-api-key-should-not-appear-1234567890", rate_limit_remaining=2500
        )

        result = credentials.to_dict()

        # Verify real security logic
        assert "api_key" not in result  # Real security: key excluded
        assert result["api_key_present"] is True  # Real logic: presence indicated
        assert result["rate_limit_remaining"] == 2500
        assert result["is_rate_limited"] is False  # Real method call
        assert "rate_limit_reset" in result


@pytest.mark.unit
class TestCertificateBundleReal:
    """Test CertificateBundle model with real business logic."""

    @pytest.fixture
    def sample_pem_data(self):
        """Create realistic PEM data for testing."""
        return {
            "certificate": """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/OvD8XAXMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjMwMTAxMTIwMDAwWhcNMjQwMTAxMTIwMDAwWjBF
-----END CERTIFICATE-----""",
            "private_key": """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
wVkwayYA+Lq6nKq3QLx3+uHfzHUGvQd84z4X3JNLr7s2VeEj1L3wlkQO1kAAAQDi
MNZoqz2XRYe3VgQ5Pg6O6E8JN11GAeK3Z8nkZcjMlI4KQOCTlmK0jllkxSfK3vz3
-----END PRIVATE KEY-----""",
            "ca_bundle": """-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
-----END CERTIFICATE-----""",
        }

    @pytest.fixture
    def temp_directory(self):
        """Create a temporary directory for file testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    def test_certificate_bundle_real_initialization(self, sample_pem_data):
        """
        Test CertificateBundle initialization with real validation logic.

        This exercises the real constructor and PEM validation without mocking.
        """
        bundle = CertificateBundle(**sample_pem_data)

        # Verify real initialization and validation
        assert bundle.certificate == sample_pem_data["certificate"]
        assert bundle.private_key == sample_pem_data["private_key"]
        assert bundle.ca_bundle == sample_pem_data["ca_bundle"]

        # Verify real full_chain logic
        expected_full_chain = sample_pem_data["certificate"] + "\n" + sample_pem_data["ca_bundle"]
        assert bundle.full_chain == expected_full_chain

    def test_certificate_bundle_custom_full_chain_real_logic(self, sample_pem_data):
        """
        Test CertificateBundle with custom full chain using real logic.

        This exercises real full_chain assignment logic.
        """
        custom_full_chain = "custom-full-chain-content-with-both-cert-and-ca"
        bundle = CertificateBundle(**sample_pem_data, full_chain=custom_full_chain)

        assert bundle.full_chain == custom_full_chain

    def test_certificate_bundle_pem_validation_real_logic(self, sample_pem_data):
        """
        Test CertificateBundle PEM validation with real validation logic.

        This exercises the real _validate_pem static method without mocking.
        """
        # Test real PEM validation success
        valid_bundle = CertificateBundle(**sample_pem_data)

        # Verify content is properly validated and stripped
        assert valid_bundle.certificate.startswith("-----BEGIN CERTIFICATE-----")
        assert valid_bundle.certificate.endswith("-----END CERTIFICATE-----")

        # Test real validation errors
        invalid_data = sample_pem_data.copy()
        invalid_data["certificate"] = ""

        with pytest.raises(ValueError) as exc_info:
            CertificateBundle(**invalid_data)
        assert "certificate content is required" in str(exc_info.value)

        # Test invalid PEM format
        invalid_data["certificate"] = "not a valid PEM certificate"
        with pytest.raises(ValueError) as exc_info:
            CertificateBundle(**invalid_data)
        assert "Invalid PEM format for certificate" in str(exc_info.value)

    def test_certificate_bundle_save_to_files_real_filesystem(
        self, sample_pem_data, temp_directory
    ):
        """
        Test CertificateBundle save_to_files with real filesystem operations.

        This exercises real file creation and permission setting without mocking
        filesystem operations.
        """
        bundle = CertificateBundle(**sample_pem_data)

        cert_path = os.path.join(temp_directory, "cert.pem")
        key_path = os.path.join(temp_directory, "key.pem")
        ca_path = os.path.join(temp_directory, "ca.pem")
        full_chain_path = os.path.join(temp_directory, "fullchain.pem")

        # Exercise real file saving logic
        result = bundle.save_to_files(
            cert_path=cert_path,
            key_path=key_path,
            ca_path=ca_path,
            full_chain_path=full_chain_path,
            file_mode=0o644,
        )

        # Verify real file creation
        assert os.path.exists(cert_path)
        assert os.path.exists(key_path)
        assert os.path.exists(ca_path)
        assert os.path.exists(full_chain_path)

        # Verify real file contents
        with open(cert_path, "r") as f:
            assert f.read() == sample_pem_data["certificate"]

        with open(key_path, "r") as f:
            assert f.read() == sample_pem_data["private_key"]

        # Verify real return value
        expected_files = {
            "certificate": cert_path,
            "private_key": key_path,
            "ca_bundle": ca_path,
            "full_chain": full_chain_path,
        }
        assert result == expected_files

        # Verify real file permissions (private key should always be 600)
        key_stat = os.stat(key_path)
        key_mode = key_stat.st_mode & 0o777
        assert key_mode == 0o600

    def test_certificate_bundle_save_to_files_without_full_chain(
        self, sample_pem_data, temp_directory
    ):
        """
        Test CertificateBundle save_to_files without full chain path.

        This exercises real conditional file creation logic.
        """
        bundle = CertificateBundle(**sample_pem_data)

        cert_path = os.path.join(temp_directory, "cert.pem")
        key_path = os.path.join(temp_directory, "key.pem")
        ca_path = os.path.join(temp_directory, "ca.pem")

        result = bundle.save_to_files(
            cert_path=cert_path,
            key_path=key_path,
            ca_path=ca_path,
            # No full_chain_path
        )

        # Verify real conditional logic
        assert "full_chain" not in result
        assert len(result) == 3

    def test_certificate_bundle_to_dict_real_security_logic(self, sample_pem_data):
        """
        Test CertificateBundle to_dict with real security logic.

        This exercises real serialization that protects sensitive data.
        """
        bundle = CertificateBundle(**sample_pem_data)

        result = bundle.to_dict()

        # Verify real security logic
        assert result["certificate"] == sample_pem_data["certificate"]
        assert result["private_key"] == "[REDACTED]"  # Real security: key redacted
        assert result["ca_bundle"] == sample_pem_data["ca_bundle"]
        assert result["full_chain"] == bundle.full_chain

        # Verify real length calculations
        assert result["certificate_length"] == len(sample_pem_data["certificate"])
        assert result["private_key_length"] == len(sample_pem_data["private_key"])
        assert result["ca_bundle_length"] == len(sample_pem_data["ca_bundle"])


@pytest.mark.unit
class TestModelsIntegrationReal:
    """Test model integration scenarios with real business logic."""

    def test_certificate_with_domain_validation_real_integration(self):
        """
        Test Certificate and DomainValidation integration with real logic.

        This exercises real integration between models without mocking.
        """
        # Create certificate for domain
        cert = Certificate(
            id="integration-cert-123",
            domains=["integration.example.com", "www.integration.example.com"],
            status=CertificateStatus.PENDING_VALIDATION,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=90),
            validation_method=ValidationMethod.HTTP_01,
        )

        # Create domain validations for certificate domains
        validations = []
        for domain in cert.domains:
            validation = DomainValidation(
                domain=domain,
                method=cert.validation_method,
                challenge_token=f'token-{domain.replace(".", "-")}',
                challenge_url=f'http://{domain}/.well-known/acme-challenge/token-{domain.replace(".", "-")}',
            )
            validations.append(validation)

        # Verify real integration
        assert len(validations) == len(cert.domains)
        assert all(v.method == cert.validation_method for v in validations)
        assert all(v.domain in cert.domains for v in validations)

    def test_api_credentials_with_rate_limiting_real_scenarios(self):
        """
        Test APICredentials rate limiting in real usage scenarios.

        This exercises real rate limiting logic without mocking.
        """
        credentials = APICredentials(
            api_key="production-api-key-1234567890123456789012", rate_limit_remaining=10
        )

        # Simulate API calls with real rate limit logic
        for i in range(10):
            assert credentials.is_rate_limited() is False
            credentials.rate_limit_remaining -= 1

        # Now rate limited
        assert credentials.is_rate_limited() is True

        # Simulate rate limit reset
        reset_time = datetime.utcnow() + timedelta(hours=1)
        credentials.update_rate_limit(remaining=5000, reset_time=reset_time)
        assert credentials.is_rate_limited() is False

    def test_certificate_bundle_with_real_certificate_data_integration(self):
        """
        Test CertificateBundle with realistic certificate data integration.

        This exercises real bundle creation from certificate model data.
        """
        # Create certificate model
        cert = Certificate(
            id="bundle-cert-456",
            domains=["bundle.example.com"],
            status=CertificateStatus.ISSUED,
            created_at=datetime.utcnow() - timedelta(days=1),
            expires_at=datetime.utcnow() + timedelta(days=89),
            validation_method=ValidationMethod.DNS_01,
        )

        # Create bundle with real PEM data
        pem_data = {
            "certificate": """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/bundle/example/cert
-----END CERTIFICATE-----""",
            "private_key": """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7bundle
-----END PRIVATE KEY-----""",
            "ca_bundle": """-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/bundle/ca/cert
-----END CERTIFICATE-----""",
        }

        bundle = CertificateBundle(**pem_data)

        # Verify real integration
        assert cert.is_valid() is True
        assert bundle.certificate.startswith("-----BEGIN CERTIFICATE-----")
        assert "[REDACTED]" in bundle.to_dict()["private_key"]

        # Real business logic: certificate and bundle should be for same domains
        # (This would be validated in real application logic)
