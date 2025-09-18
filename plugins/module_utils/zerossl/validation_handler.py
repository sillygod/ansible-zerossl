# -*- coding: utf-8 -*-
"""
ZeroSSL Validation Handler.

This module handles domain validation processes for both HTTP-01 and DNS-01
validation methods, including file placement and DNS record management.
"""

import time
import requests
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

import dns.resolver
from dns.resolver import NXDOMAIN, NoAnswer

from .exceptions import (
    ZeroSSLValidationError,
    ZeroSSLFileSystemError,
    ZeroSSLTimeoutError
)
from .utils import parse_validation_url, is_wildcard_domain


class ValidationHandler:
    """
    Domain validation handler for HTTP-01 and DNS-01 methods.

    This class provides functionality to prepare validation files,
    manage DNS records, and verify domain ownership for certificate validation.
    """

    def __init__(
        self,
        http_timeout: int = 30,
        dns_timeout: int = 60,
        max_retries: int = 3
    ):
        """
        Initialize Validation Handler.

        Args:
            http_timeout: Timeout for HTTP validation requests
            dns_timeout: Timeout for DNS resolution
            max_retries: Maximum retry attempts for validations
        """
        self.http_timeout = http_timeout
        self.dns_timeout = dns_timeout
        self.max_retries = max_retries

    def prepare_http_validation(self, validation_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Prepare HTTP validation files from ZeroSSL validation data.

        Args:
            validation_data: Validation data from ZeroSSL API

        Returns:
            List of validation file information

        Raises:
            ZeroSSLValidationError: If validation data is malformed
        """
        validation_files = []

        for domain, domain_data in validation_data.items():
            if 'file_validation_url_http' not in domain_data:
                raise ZeroSSLValidationError(
                    f"Missing HTTP validation URL for domain: {domain}",
                    domain=domain,
                    validation_method="HTTP_CSR_HASH"
                )

            if 'file_validation_content' not in domain_data:
                raise ZeroSSLValidationError(
                    f"Missing validation content for domain: {domain}",
                    domain=domain,
                    validation_method="HTTP_CSR_HASH"
                )

            url_info = parse_validation_url(domain_data['file_validation_url_http'])

            validation_file = {
                'domain': domain,
                'filename': url_info['filename'],
                'content': domain_data['file_validation_content'],
                'url_path': url_info['path'],
                'full_url': domain_data['file_validation_url_http']
            }

            validation_files.append(validation_file)

        return validation_files

    def _extract_filename_from_url(self, url: str) -> str:
        """Extract filename from validation URL."""
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        return path_parts[-1] if path_parts else ''

    def _construct_file_path(self, base_path: str, url_path: str) -> str:
        """Construct full file path for validation file."""
        # Remove leading slash from url_path
        relative_path = url_path.lstrip('/')
        return str(Path(base_path) / relative_path)

    def place_validation_files(
        self,
        validation_files: List[Dict[str, Any]],
        web_root: str
    ) -> Dict[str, Any]:
        """
        Place validation files in the web root directory.

        Args:
            validation_files: List of validation file data
            web_root: Web server document root path

        Returns:
            Result of file placement operation

        Raises:
            ZeroSSLFileSystemError: If file placement fails
        """
        result = {
            'success': True,
            'files_created': [],
            'error': None
        }

        created_files = []

        try:
            web_root_path = Path(web_root)

            for vf in validation_files:
                # Construct full file path
                file_path = self._construct_file_path(web_root, vf['url_path'])
                file_path_obj = Path(file_path)

                # Create directories if they don't exist
                file_path_obj.parent.mkdir(parents=True, exist_ok=True)

                # Write validation content
                file_path_obj.write_text(vf['content'])

                # Set appropriate permissions
                file_path_obj.chmod(0o644)

                file_info = {
                    'domain': vf['domain'],
                    'path': str(file_path),
                    'content': vf['content'],
                    'url_path': vf['url_path']
                }

                created_files.append(file_info)
                result['files_created'].append(file_info)

        except PermissionError as e:
            result['success'] = False
            result['error'] = f"Permission denied: {e}"

            # Clean up any files we managed to create
            self._cleanup_files([f['path'] for f in created_files])

        except Exception as e:
            result['success'] = False
            result['error'] = f"Failed to place validation files: {e}"

            # Clean up any files we managed to create
            self._cleanup_files([f['path'] for f in created_files])

        return result

    def _cleanup_files(self, file_paths: List[str]):
        """Clean up created files on error."""
        for file_path in file_paths:
            try:
                Path(file_path).unlink(missing_ok=True)
            except Exception:
                pass  # Ignore cleanup errors

    def verify_http_validation(
        self,
        validation_url: str,
        expected_content: str
    ) -> Dict[str, Any]:
        """
        Verify HTTP validation by fetching the validation URL.

        Args:
            validation_url: URL to verify
            expected_content: Expected validation content

        Returns:
            Verification result

        Raises:
            ZeroSSLValidationError: If verification fails
        """
        result = {
            'accessible': False,
            'content_match': False,
            'status_code': None,
            'error': None
        }

        try:
            response = requests.get(validation_url, timeout=self.http_timeout)
            result['status_code'] = response.status_code

            if response.status_code == 200:
                result['accessible'] = True
                result['content_match'] = response.text.strip() == expected_content.strip()
            else:
                result['error'] = f"HTTP {response.status_code}: Validation URL not accessible"

        except requests.exceptions.Timeout:
            result['error'] = "Request timeout while accessing validation URL"
        except requests.exceptions.ConnectionError:
            result['error'] = "Connection failed to validation URL"
        except Exception as e:
            result['error'] = f"Unexpected error: {e}"

        return result

    def prepare_dns_validation(self, validation_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Prepare DNS validation records from ZeroSSL validation data.

        Args:
            validation_data: Validation data from ZeroSSL API

        Returns:
            List of DNS record information

        Raises:
            ZeroSSLValidationError: If validation data is malformed
        """
        dns_records = []

        for domain, domain_data in validation_data.items():
            if 'dns_txt_name' not in domain_data:
                raise ZeroSSLValidationError(
                    f"Missing DNS TXT record name for domain: {domain}",
                    domain=domain,
                    validation_method="DNS_CSR_HASH"
                )

            if 'dns_txt_value' not in domain_data:
                raise ZeroSSLValidationError(
                    f"Missing DNS TXT record value for domain: {domain}",
                    domain=domain,
                    validation_method="DNS_CSR_HASH"
                )

            dns_record = {
                'domain': domain,
                'record_name': self._parse_dns_record_name(domain_data['dns_txt_name']),
                'record_type': 'TXT',
                'record_value': domain_data['dns_txt_value']
            }

            dns_records.append(dns_record)

        return dns_records

    def _parse_dns_record_name(self, record_name: str) -> str:
        """Parse and validate DNS record name."""
        # ZeroSSL provides the full record name, just return it
        return record_name.strip()

    def generate_dns_instructions(self, dns_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate human-readable DNS setup instructions.

        Args:
            dns_records: List of DNS records to create

        Returns:
            DNS setup instructions
        """
        instructions = {
            'records_to_create': dns_records,
            'instructions': self._format_dns_instructions(dns_records)
        }

        return instructions

    def _format_dns_instructions(self, dns_records: List[Dict[str, Any]]) -> str:
        """Format DNS records as human-readable instructions."""
        instructions = ["DNS Records to Create:"]
        instructions.append("=" * 40)

        for i, record in enumerate(dns_records, 1):
            instructions.extend([
                f"{i}. Domain: {record['domain']}",
                f"   Record Type: {record['record_type']}",
                f"   Record Name: {record['record_name']}",
                f"   Record Value: {record['record_value']}",
                ""
            ])

        instructions.extend([
            "Instructions:",
            "1. Log into your DNS provider's control panel",
            "2. Navigate to DNS management for your domain",
            "3. Create TXT records as specified above",
            "4. Wait for DNS propagation (usually 5-30 minutes)",
            "5. Trigger validation once records are live"
        ])

        return "\n".join(instructions)

    def verify_dns_validation(
        self,
        record_name: str,
        expected_value: str
    ) -> Dict[str, Any]:
        """
        Verify DNS validation by checking TXT record.

        Args:
            record_name: DNS record name to check
            expected_value: Expected TXT record value

        Returns:
            Verification result
        """
        result = {
            'record_exists': False,
            'value_match': False,
            'actual_values': [],
            'error': None
        }

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.dns_timeout
            resolver.lifetime = self.dns_timeout

            answers = resolver.resolve(record_name, 'TXT')
            result['record_exists'] = True

            # Extract TXT record values
            for rdata in answers:
                txt_value = rdata.to_text().strip('"')
                result['actual_values'].append(txt_value)

                if txt_value == expected_value:
                    result['value_match'] = True

        except NXDOMAIN:
            result['error'] = f"DNS record not found: {record_name}"
        except NoAnswer:
            result['error'] = f"No TXT record found for: {record_name}"
        except Exception as e:
            result['error'] = f"DNS resolution failed: {e}"

        return result

    def suggest_validation_method(self, domains: List[str]) -> str:
        """
        Suggest the best validation method for the given domains.

        Args:
            domains: List of domains to validate

        Returns:
            Suggested validation method
        """
        # If any domain is a wildcard, DNS validation is required
        for domain in domains:
            if is_wildcard_domain(domain):
                return 'DNS_CSR_HASH'

        # For regular domains, HTTP validation is usually easier
        return 'HTTP_CSR_HASH'

    def cleanup_validation_files(self, file_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Clean up validation files after validation.

        Args:
            file_list: List of file information to clean up

        Returns:
            Cleanup result
        """
        result = {
            'success': True,
            'files_removed': [],
            'errors': []
        }

        for file_info in file_list:
            try:
                file_path = Path(file_info['path'])
                if file_path.exists():
                    file_path.unlink()
                    result['files_removed'].append(file_info['path'])

                # Try to remove empty parent directories
                self._cleanup_empty_directories(file_path.parent)

            except Exception as e:
                result['errors'].append({
                    'file': file_info['path'],
                    'error': str(e)
                })

        if result['errors']:
            result['success'] = False

        return result

    def _cleanup_empty_directories(self, directory: Path):
        """Remove empty parent directories up to .well-known."""
        try:
            # Only clean up directories we created (.well-known/pki-validation)
            if directory.name == 'pki-validation' and directory.parent.name == '.well-known':
                if not any(directory.iterdir()):
                    directory.rmdir()

                # Check parent .well-known directory
                well_known_dir = directory.parent
                if not any(well_known_dir.iterdir()):
                    well_known_dir.rmdir()

        except Exception:
            pass  # Ignore errors in cleanup

    def poll_validation_status(
        self,
        api_client,
        certificate_id: str,
        max_attempts: int = 30,
        poll_interval: int = 10
    ) -> Dict[str, Any]:
        """
        Poll certificate validation status until completion.

        Args:
            api_client: ZeroSSL API client instance
            certificate_id: Certificate ID to poll
            max_attempts: Maximum polling attempts
            poll_interval: Seconds between polls

        Returns:
            Final validation status

        Raises:
            ZeroSSLTimeoutError: If polling times out
            ZeroSSLValidationError: If validation fails
        """
        for attempt in range(max_attempts):
            try:
                cert_info = api_client.get_certificate(certificate_id)

                # Check for completion
                if cert_info['status'] == 'issued':
                    return {
                        'certificate_id': certificate_id,
                        'final_status': 'issued',
                        'validation_completed': True,
                        'attempts': attempt + 1
                    }

                # Check for failure
                failure_statuses = ['canceled', 'expired', 'failed']
                if cert_info['status'] in failure_statuses:
                    raise ZeroSSLValidationError(
                        f"Certificate validation failed with status: {cert_info['status']}",
                        validation_details={'final_status': cert_info['status']}
                    )

                # Continue polling
                if attempt < max_attempts - 1:
                    time.sleep(poll_interval)

            except ZeroSSLValidationError:
                raise
            except Exception as e:
                if attempt == max_attempts - 1:
                    raise ZeroSSLValidationError(f"Validation polling failed: {e}")

        # Timeout reached
        raise ZeroSSLTimeoutError(
            f"Validation polling timed out after {max_attempts} attempts",
            timeout_duration=max_attempts * poll_interval,
            operation="validation_polling"
        )

    def aggregate_validation_errors(
        self,
        validation_errors: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Aggregate validation errors from multiple domains.

        Args:
            validation_errors: List of domain validation errors

        Returns:
            Aggregated error information
        """
        return {
            'message': f"Multiple domains failed validation: {len(validation_errors)} errors",
            'failed_count': len(validation_errors),
            'domain_errors': validation_errors,
            'summary': [f"{err['domain']}: {err['error']}" for err in validation_errors]
        }
