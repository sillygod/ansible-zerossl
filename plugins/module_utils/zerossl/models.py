# -*- coding: utf-8 -*-
"""
ZeroSSL data models and enumerations.

This module defines the core data structures used throughout the ZeroSSL
plugin, including certificates, domain validations, and status enumerations.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
import re


class CertificateStatus(Enum):
    """Certificate status enumeration matching ZeroSSL API responses."""
    DRAFT = "draft"
    PENDING_VALIDATION = "pending_validation"
    ISSUED = "issued"
    EXPIRED = "expired"
    CANCELED = "canceled"


class ValidationMethod(Enum):
    """Validation method enumeration matching ZeroSSL API formats."""
    HTTP_01 = "HTTP_CSR_HASH"
    DNS_01 = "DNS_CSR_HASH"


class ValidationStatus(Enum):
    """Domain validation status enumeration."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    VALID = "valid"
    INVALID = "invalid"


class OperationState(Enum):
    """Plugin operation state enumeration."""
    PRESENT = "present"
    REQUEST = "request"
    VALIDATE = "validate"
    DOWNLOAD = "download"
    ABSENT = "absent"
    CHECK_RENEWAL = "check_renew_or_create"


class Certificate:
    """
    Represents an SSL/TLS certificate managed through ZeroSSL API.

    Attributes:
        id: ZeroSSL certificate identifier
        domains: List of domains covered by certificate
        common_name: Primary domain (first in domains list)
        status: Current certificate state
        created_at: Certificate creation timestamp
        expires_at: Certificate expiration timestamp
        validation_method: Domain validation approach used
        certificate_path: Local filesystem path where certificate is stored
    """

    def __init__(
        self,
        id: str,
        domains: List[str],
        status: CertificateStatus,
        created_at: datetime,
        expires_at: datetime,
        validation_method: ValidationMethod,
        certificate_path: Optional[str] = None
    ):
        self.id = id
        self.domains = self._validate_domains(domains)
        self.common_name = domains[0] if domains else ""
        self.status = status
        self.created_at = created_at
        self.expires_at = expires_at
        self.validation_method = validation_method
        self.certificate_path = certificate_path

    @staticmethod
    def _validate_domains(domains: List[str]) -> List[str]:
        """Validate domain list format and content."""
        if not domains:
            raise ValueError("At least one domain is required")

        domain_pattern = re.compile(
            r'^(?!-)[A-Za-z0-9-*]{1,63}(?<!-)\.?(?:[A-Za-z0-9-*]{1,63}(?<!-)\.)*[A-Za-z]{2,}$'
        )

        for domain in domains:
            if not domain_pattern.match(domain):
                raise ValueError(f"Invalid domain format: {domain}")

        return domains

    def is_valid(self) -> bool:
        """Check if certificate is in a valid state."""
        return self.status == CertificateStatus.ISSUED

    def is_expired(self) -> bool:
        """Check if certificate has expired."""
        return self.expires_at <= datetime.utcnow()

    def days_until_expiry(self) -> int:
        """Calculate days until certificate expires."""
        delta = self.expires_at - datetime.utcnow()
        return delta.days

    def needs_renewal(self, threshold_days: int = 30) -> bool:
        """Check if certificate needs renewal based on threshold."""
        return self.days_until_expiry() <= threshold_days

    def to_dict(self) -> Dict[str, Any]:
        """Convert certificate to dictionary representation."""
        return {
            'id': self.id,
            'domains': self.domains,
            'common_name': self.common_name,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'validation_method': self.validation_method.value,
            'certificate_path': self.certificate_path,
            'is_valid': self.is_valid(),
            'is_expired': self.is_expired(),
            'days_until_expiry': self.days_until_expiry()
        }

    @classmethod
    def from_zerossl_response(cls, response: Dict[str, Any]) -> 'Certificate':
        """Create Certificate instance from ZeroSSL API response."""
        # Parse dates
        created_at = datetime.strptime(response['created'], '%Y-%m-%d %H:%M:%S')
        expires_at = datetime.strptime(response['expires'], '%Y-%m-%d %H:%M:%S')

        # Extract domains
        domains = [response['common_name']]
        if response.get('additional_domains'):
            additional = response['additional_domains'].split(',')
            domains.extend([d.strip() for d in additional if d.strip()])

        # Determine validation method (default to HTTP)
        validation_method = ValidationMethod.HTTP_01

        return cls(
            id=response['id'],
            domains=domains,
            status=CertificateStatus(response['status']),
            created_at=created_at,
            expires_at=expires_at,
            validation_method=validation_method
        )


class DomainValidation:
    """
    Represents the validation process for proving domain ownership.

    Attributes:
        domain: Domain being validated
        method: Validation approach (HTTP-01 or DNS-01)
        challenge_token: Validation token provided by ZeroSSL
        challenge_url: URL where validation file should be placed (HTTP-01)
        dns_record: TXT record content for DNS validation (DNS-01)
        status: Current validation state
        validated_at: Timestamp when validation completed
    """

    def __init__(
        self,
        domain: str,
        method: ValidationMethod,
        challenge_token: str,
        challenge_url: Optional[str] = None,
        dns_record: Optional[str] = None,
        status: ValidationStatus = ValidationStatus.PENDING,
        validated_at: Optional[datetime] = None
    ):
        self.domain = domain
        self.method = method
        self.challenge_token = challenge_token
        self.challenge_url = challenge_url
        self.dns_record = dns_record
        self.status = status
        self.validated_at = validated_at

        self._validate()

    def _validate(self):
        """Validate domain validation configuration."""
        if not self.domain:
            raise ValueError("Domain is required")

        if not self.challenge_token:
            raise ValueError("Challenge token is required")

        if self.method == ValidationMethod.HTTP_01 and not self.challenge_url:
            raise ValueError("Challenge URL is required for HTTP-01 validation")

        if self.method == ValidationMethod.DNS_01 and not self.dns_record:
            raise ValueError("DNS record is required for DNS-01 validation")

    def is_complete(self) -> bool:
        """Check if validation is complete."""
        return self.status == ValidationStatus.VALID and self.validated_at is not None

    def mark_validated(self):
        """Mark validation as complete."""
        self.status = ValidationStatus.VALID
        self.validated_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert domain validation to dictionary representation."""
        return {
            'domain': self.domain,
            'method': self.method.value,
            'challenge_token': self.challenge_token,
            'challenge_url': self.challenge_url,
            'dns_record': self.dns_record,
            'status': self.status.value,
            'validated_at': self.validated_at.isoformat() if self.validated_at else None,
            'is_complete': self.is_complete()
        }


class APICredentials:
    """
    Represents ZeroSSL API authentication information.

    Attributes:
        api_key: ZeroSSL API access key (sensitive)
        rate_limit_remaining: Remaining API calls in current period
        rate_limit_reset: When rate limit counter resets
    """

    def __init__(
        self,
        api_key: str,
        rate_limit_remaining: int = 5000,
        rate_limit_reset: Optional[datetime] = None
    ):
        self.api_key = self._validate_api_key(api_key)
        self.rate_limit_remaining = rate_limit_remaining
        self.rate_limit_reset = rate_limit_reset or datetime.utcnow()

    @staticmethod
    def _validate_api_key(api_key: str) -> str:
        """Validate API key format."""
        if not api_key:
            raise ValueError("API key is required")

        if len(api_key) < 20:
            raise ValueError("API key appears to be invalid (too short)")

        return api_key

    def is_rate_limited(self) -> bool:
        """Check if API is currently rate limited."""
        return self.rate_limit_remaining <= 0

    def update_rate_limit(self, remaining: int, reset_time: datetime):
        """Update rate limit information."""
        self.rate_limit_remaining = remaining
        self.rate_limit_reset = reset_time

    def to_dict(self) -> Dict[str, Any]:
        """Convert credentials to dictionary (excluding sensitive data)."""
        return {
            'api_key_present': bool(self.api_key),
            'rate_limit_remaining': self.rate_limit_remaining,
            'rate_limit_reset': self.rate_limit_reset.isoformat(),
            'is_rate_limited': self.is_rate_limited()
        }


class CertificateBundle:
    """
    Represents the complete certificate package for deployment.

    Attributes:
        certificate: Primary certificate content (PEM format)
        private_key: Private key content (PEM format)
        ca_bundle: Certificate authority chain (PEM format)
        full_chain: Combined certificate + CA bundle for web servers
    """

    def __init__(
        self,
        certificate: str,
        private_key: str,
        ca_bundle: str,
        full_chain: Optional[str] = None
    ):
        self.certificate = self._validate_pem(certificate, "certificate")
        self.private_key = self._validate_pem(private_key, "private key")
        self.ca_bundle = self._validate_pem(ca_bundle, "CA bundle")
        self.full_chain = full_chain or (certificate + "\n" + ca_bundle)

    @staticmethod
    def _validate_pem(content: str, component_name: str) -> str:
        """Validate PEM format content."""
        if not content:
            raise ValueError(f"{component_name} content is required")

        if "-----BEGIN" not in content or "-----END" not in content:
            raise ValueError(f"Invalid PEM format for {component_name}")

        return content.strip()

    def save_to_files(
        self,
        cert_path: str,
        key_path: str,
        ca_path: str,
        full_chain_path: Optional[str] = None,
        file_mode: int = 0o600
    ) -> Dict[str, str]:
        """Save certificate bundle to filesystem."""
        import os
        from pathlib import Path

        files_written = {}

        # Write certificate
        cert_file = Path(cert_path)
        cert_file.parent.mkdir(parents=True, exist_ok=True)
        cert_file.write_text(self.certificate)
        os.chmod(cert_path, file_mode)
        files_written['certificate'] = cert_path

        # Write private key
        key_file = Path(key_path)
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text(self.private_key)
        os.chmod(key_path, 0o600)  # Always 600 for private keys
        files_written['private_key'] = key_path

        # Write CA bundle
        ca_file = Path(ca_path)
        ca_file.parent.mkdir(parents=True, exist_ok=True)
        ca_file.write_text(self.ca_bundle)
        os.chmod(ca_path, file_mode)
        files_written['ca_bundle'] = ca_path

        # Write full chain if requested
        if full_chain_path:
            full_chain_file = Path(full_chain_path)
            full_chain_file.parent.mkdir(parents=True, exist_ok=True)
            full_chain_file.write_text(self.full_chain)
            os.chmod(full_chain_path, file_mode)
            files_written['full_chain'] = full_chain_path

        return files_written

    def to_dict(self) -> Dict[str, Any]:
        """Convert certificate bundle to dictionary representation."""
        return {
            'certificate': self.certificate,
            'private_key': '[REDACTED]',  # Never expose private key
            'ca_bundle': self.ca_bundle,
            'full_chain': self.full_chain,
            'certificate_length': len(self.certificate),
            'private_key_length': len(self.private_key),
            'ca_bundle_length': len(self.ca_bundle)
        }
