# -*- coding: utf-8 -*-
"""
ZeroSSL Certificate Manager.

This module provides high-level certificate lifecycle management functionality,
including creation, validation, renewal, and download operations.
"""

import time
import zipfile
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from io import BytesIO

from .api_client import ZeroSSLAPIClient
from .validation_handler import ValidationHandler
from .models import Certificate, CertificateStatus, CertificateBundle
from .exceptions import (
    ZeroSSLCertificateError,
    ZeroSSLValidationError,
    ZeroSSLHTTPError,
    ZeroSSLTimeoutError
)
from .utils import validate_domains, domains_overlap


class CertificateManager:
    """
    High-level certificate lifecycle management.

    This class provides a simplified interface for managing SSL certificates
    through the ZeroSSL API, handling the complex workflows involved in
    certificate creation, validation, and deployment.
    """

    def __init__(
        self,
        api_key: str,
        api_client: Optional[ZeroSSLAPIClient] = None,
        validation_handler: Optional[ValidationHandler] = None,
        enable_caching: bool = False
    ):
        """
        Initialize Certificate Manager.

        Args:
            api_key: ZeroSSL API access key
            api_client: Optional custom API client instance
            validation_handler: Optional custom validation handler
            enable_caching: Whether to enable certificate info caching
        """
        self.api_key = api_key
        self.api_client = api_client or ZeroSSLAPIClient(api_key)
        self.validation_handler = validation_handler or ValidationHandler()
        self.enable_caching = enable_caching

        # Simple in-memory cache
        self._cache = {} if enable_caching else None
        self._cache_ttl = 300  # 5 minutes

    def create_certificate(
        self,
        domains: List[str],
        csr: str,
        validation_method: str,
        validity_days: int = 90
    ) -> Dict[str, Any]:
        """
        Create a new certificate.

        Args:
            domains: List of domains for the certificate
            csr: Certificate Signing Request content
            validation_method: Validation method (HTTP_CSR_HASH or DNS_CSR_HASH)
            validity_days: Certificate validity period

        Returns:
            Dictionary with certificate creation results

        Raises:
            ZeroSSLCertificateError: If certificate creation fails
        """
        try:
            # Validate domains
            validated_domains = validate_domains(domains)

            # Create certificate via API
            response = self.api_client.create_certificate(
                domains=validated_domains,
                csr=csr,
                validity_days=validity_days
            )

            # Extract validation information
            validation_files = []
            dns_records = []

            if 'validation' in response and 'other_methods' in response['validation']:
                validation_data = response['validation']['other_methods']

                if validation_method == 'HTTP_CSR_HASH':
                    validation_files = self.validation_handler.prepare_http_validation(validation_data)
                elif validation_method == 'DNS_CSR_HASH':
                    dns_records = self.validation_handler.prepare_dns_validation(validation_data)

            return {
                'certificate_id': response['id'],
                'status': response['status'],
                'domains': validated_domains,
                'validation_method': validation_method,
                'validation_files': validation_files,
                'dns_records': dns_records,
                'created': True,
                'changed': True
            }

        except Exception as e:
            if isinstance(e, (ZeroSSLHTTPError, ZeroSSLValidationError)):
                raise
            raise ZeroSSLCertificateError(
                f"Failed to create certificate: {e}",
                operation="create"
            )

    def get_certificate_status(self, certificate_id: str) -> Dict[str, Any]:
        """
        Get certificate status and information.

        Args:
            certificate_id: ZeroSSL certificate ID

        Returns:
            Certificate status information

        Raises:
            ZeroSSLCertificateError: If status retrieval fails
        """
        # Check cache first
        if self._cache:
            cache_key = f"status_{certificate_id}"
            if cache_key in self._cache:
                cached_data, timestamp = self._cache[cache_key]
                if time.time() - timestamp < self._cache_ttl:
                    return cached_data

        try:
            response = self.api_client.get_certificate(certificate_id)

            status_info = {
                'certificate_id': certificate_id,
                'status': response['status'],
                'expires': response.get('expires'),
                'common_name': response.get('common_name'),
                'additional_domains': response.get('additional_domains', ''),
                'created': response.get('created'),
                'validation_completed': response.get('validation_completed', False)
            }

            # Cache the result
            if self._cache:
                cache_key = f"status_{certificate_id}"
                self._cache[cache_key] = (status_info, time.time())

            return status_info

        except Exception as e:
            if isinstance(e, ZeroSSLHTTPError):
                raise
            raise ZeroSSLCertificateError(
                f"Failed to get certificate status: {e}",
                certificate_id=certificate_id,
                operation="status_check"
            )

    def find_certificate_for_domains(self, domains: List[str]) -> Optional[str]:
        """
        Find existing certificate that covers the specified domains.

        Args:
            domains: List of domains to find certificate for

        Returns:
            Certificate ID if found, None otherwise

        Raises:
            ZeroSSLCertificateError: If search fails
        """
        try:
            validated_domains = validate_domains(domains)

            # List all issued certificates
            response = self.api_client.list_certificates(status='issued')

            for cert_data in response.get('results', []):
                if self._domains_match(validated_domains, cert_data):
                    return cert_data['id']

            return None

        except Exception as e:
            if isinstance(e, ZeroSSLHTTPError):
                raise
            raise ZeroSSLCertificateError(
                f"Failed to search certificates: {e}",
                operation="search"
            )

    def _domains_match(self, requested_domains: List[str], certificate: Dict[str, Any]) -> bool:
        """
        Check if certificate covers all requested domains.

        Args:
            requested_domains: Domains that need to be covered
            certificate: Certificate data from API

        Returns:
            True if certificate covers all requested domains
        """
        cert_domains = [certificate['common_name']]

        if certificate.get('additional_domains'):
            additional = certificate['additional_domains'].split(',')
            cert_domains.extend([d.strip() for d in additional if d.strip()])

        # Check if all requested domains are covered
        for requested_domain in requested_domains:
            domain_covered = False
            for cert_domain in cert_domains:
                if domains_overlap(cert_domain, requested_domain):
                    domain_covered = True
                    break

            if not domain_covered:
                return False

        return True

    def needs_renewal(
        self,
        domains: List[str],
        threshold_days: int = 30
    ) -> bool:
        """
        Check if domains need certificate renewal.

        Args:
            domains: List of domains to check
            threshold_days: Renewal threshold in days

        Returns:
            True if renewal is needed

        Raises:
            ZeroSSLCertificateError: If renewal check fails
        """
        try:
            certificate_id = self.find_certificate_for_domains(domains)

            if not certificate_id:
                # No existing certificate, renewal needed
                return True

            status_info = self.get_certificate_status(certificate_id)

            # Check if certificate is in usable status
            if not self._is_usable_status(status_info['status']):
                return True

            # Check expiration
            if status_info['expires']:
                expires_at = datetime.strptime(status_info['expires'], '%Y-%m-%d %H:%M:%S')
                days_until_expiry = (expires_at - datetime.utcnow()).days

                return days_until_expiry <= threshold_days

            # If no expiration date, assume renewal needed
            return True

        except Exception as e:
            if isinstance(e, ZeroSSLCertificateError):
                raise
            raise ZeroSSLCertificateError(
                f"Failed to check renewal status: {e}",
                operation="renewal_check"
            )

    def _is_usable_status(self, status: str) -> bool:
        """Check if certificate status is usable."""
        usable_statuses = ['issued', 'pending_validation', 'draft']
        return status in usable_statuses

    def _is_valid_status(self, status: str) -> bool:
        """Check if certificate status is valid."""
        try:
            CertificateStatus(status)
            return True
        except ValueError:
            return False

    def _days_until_expiry(self, certificate: Dict[str, Any]) -> int:
        """Calculate days until certificate expires."""
        if not certificate.get('expires'):
            return -1

        expires_at = datetime.strptime(certificate['expires'], '%Y-%m-%d %H:%M:%S')
        return (expires_at - datetime.utcnow()).days

    def validate_certificate(
        self,
        certificate_id: str,
        validation_method: str
    ) -> Dict[str, Any]:
        """
        Trigger certificate validation.

        Args:
            certificate_id: ZeroSSL certificate ID
            validation_method: Validation method

        Returns:
            Validation result

        Raises:
            ZeroSSLValidationError: If validation fails
        """
        try:
            response = self.api_client.validate_certificate(certificate_id, validation_method)

            return {
                'certificate_id': certificate_id,
                'validation_method': validation_method,
                'success': response.get('success', False),
                'validation_completed': response.get('validation_completed', False),
                'changed': True
            }

        except Exception as e:
            if isinstance(e, (ZeroSSLHTTPError, ZeroSSLValidationError)):
                raise
            raise ZeroSSLValidationError(
                f"Certificate validation failed: {e}",
                validation_method=validation_method
            )

    def download_certificate(self, certificate_id: str) -> Dict[str, Any]:
        """
        Download and process certificate files.

        Args:
            certificate_id: ZeroSSL certificate ID

        Returns:
            Certificate bundle data

        Raises:
            ZeroSSLCertificateError: If download fails
        """
        try:
            # Download certificate ZIP
            zip_content = self.api_client.download_certificate(certificate_id)

            # Process ZIP contents
            bundle_data = self._process_certificate_zip(zip_content)

            return bundle_data

        except Exception as e:
            if isinstance(e, ZeroSSLHTTPError):
                raise
            raise ZeroSSLCertificateError(
                f"Failed to download certificate: {e}",
                certificate_id=certificate_id,
                operation="download"
            )

    def _process_certificate_zip(self, zip_content: bytes) -> Dict[str, Any]:
        """
        Process certificate ZIP file contents.

        Args:
            zip_content: ZIP file content from ZeroSSL

        Returns:
            Processed certificate bundle

        Raises:
            ZeroSSLCertificateError: If processing fails
        """
        try:
            bundle_data = {
                'certificate': '',
                'private_key': '',
                'ca_bundle': '',
                'full_chain': ''
            }

            with zipfile.ZipFile(BytesIO(zip_content), 'r') as zip_file:
                for file_info in zip_file.filelist:
                    file_content = zip_file.read(file_info.filename).decode('utf-8')

                    if file_info.filename == 'certificate.crt':
                        bundle_data['certificate'] = file_content
                    elif file_info.filename == 'ca_bundle.crt':
                        bundle_data['ca_bundle'] = file_content
                    elif file_info.filename == 'private.key':
                        bundle_data['private_key'] = file_content

            # Create full chain
            if bundle_data['certificate'] and bundle_data['ca_bundle']:
                bundle_data['full_chain'] = (
                    bundle_data['certificate'].strip() + '\n' +
                    bundle_data['ca_bundle'].strip()
                )

            # Validate that we have all required components
            required_components = ['certificate', 'ca_bundle']
            missing_components = [comp for comp in required_components
                                 if not bundle_data[comp]]

            if missing_components:
                raise ZeroSSLCertificateError(
                    f"Missing certificate components: {', '.join(missing_components)}",
                    operation="process"
                )

            return bundle_data

        except zipfile.BadZipFile:
            raise ZeroSSLCertificateError(
                "Invalid ZIP file received from ZeroSSL",
                operation="process"
            )
        except Exception as e:
            raise ZeroSSLCertificateError(
                f"Failed to process certificate ZIP: {e}",
                operation="process"
            )

    def poll_validation_status(
        self,
        certificate_id: str,
        max_attempts: int = 30,
        poll_interval: int = 10
    ) -> Dict[str, Any]:
        """
        Poll certificate validation status until completion.

        Args:
            certificate_id: ZeroSSL certificate ID
            max_attempts: Maximum polling attempts
            poll_interval: Interval between polls in seconds

        Returns:
            Final validation status

        Raises:
            ZeroSSLTimeoutError: If polling times out
            ZeroSSLValidationError: If validation fails
        """
        for attempt in range(max_attempts):
            try:
                status_info = self.get_certificate_status(certificate_id)

                # Check for completion
                if status_info['status'] == 'issued':
                    return {
                        'certificate_id': certificate_id,
                        'final_status': 'issued',
                        'validation_completed': True,
                        'attempts': attempt + 1
                    }

                # Check for failure
                failure_statuses = ['canceled', 'expired', 'failed']
                if status_info['status'] in failure_statuses:
                    raise ZeroSSLValidationError(
                        f"Certificate validation failed with status: {status_info['status']}"
                    )

                # Continue polling
                if attempt < max_attempts - 1:
                    time.sleep(poll_interval)

            except (ZeroSSLValidationError, ZeroSSLCertificateError):
                raise
            except Exception as e:
                # On unexpected errors, continue polling unless it's the last attempt
                if attempt == max_attempts - 1:
                    raise ZeroSSLCertificateError(
                        f"Validation polling failed: {e}",
                        certificate_id=certificate_id,
                        operation="validation_polling"
                    )

        # If we get here, polling timed out
        raise ZeroSSLTimeoutError(
            f"Validation polling timed out after {max_attempts} attempts",
            timeout_duration=max_attempts * poll_interval,
            operation="validation_polling"
        )

    def create_certificate_bundle(
        self,
        certificate_content: str,
        private_key_content: str,
        ca_bundle_content: str
    ) -> CertificateBundle:
        """
        Create a certificate bundle object.

        Args:
            certificate_content: Certificate PEM content
            private_key_content: Private key PEM content
            ca_bundle_content: CA bundle PEM content

        Returns:
            CertificateBundle instance

        Raises:
            ZeroSSLCertificateError: If bundle creation fails
        """
        try:
            return CertificateBundle(
                certificate=certificate_content,
                private_key=private_key_content,
                ca_bundle=ca_bundle_content
            )
        except Exception as e:
            raise ZeroSSLCertificateError(
                f"Failed to create certificate bundle: {e}",
                operation="bundle_creation"
            )
