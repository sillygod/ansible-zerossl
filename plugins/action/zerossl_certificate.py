# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Ansible ZeroSSL Plugin Contributors
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zerossl_certificate
author: Ansible ZeroSSL Plugin Contributors
version_added: "2.10"
short_description: Manage SSL certificates using ZeroSSL API
description:
  - Create, validate, download, and manage SSL certificates through the ZeroSSL API
  - Supports both HTTP-01 and DNS-01 domain validation methods
  - Provides complete certificate lifecycle management including automatic renewal
  - Handles multi-domain (SAN) certificates and wildcard certificates
  - Implements proper retry logic and rate limiting for robust operation

options:
  api_key:
    description:
      - ZeroSSL API access key
      - Can be obtained from the ZeroSSL dashboard
      - Store securely using Ansible Vault
    required: true
    type: str

  domains:
    description:
      - List of domains to include in the certificate
      - First domain becomes the common name
      - Additional domains are added as Subject Alternative Names (SAN)
      - Wildcard domains (*.example.com) require DNS validation
    required: true
    type: list
    elements: str

  state:
    description:
      - Desired state of the certificate
      - C(present) - Ensure certificate exists and is valid, create/renew if needed
      - C(request) - Create certificate request and return validation challenges
      - C(validate) - Validate a pending certificate
      - C(download) - Download an issued certificate
      - C(absent) - Cancel/remove certificate
      - C(check_renew_or_create) - Check if certificate needs renewal
    default: present
    choices: ['present', 'request', 'validate', 'download', 'absent', 'check_renew_or_create']
    type: str

  validation_method:
    description:
      - Domain validation method
      - C(HTTP_CSR_HASH) - HTTP-01 validation using file placement
      - C(DNS_CSR_HASH) - DNS-01 validation using TXT records
      - DNS validation required for wildcard certificates
    default: HTTP_CSR_HASH
    choices: ['HTTP_CSR_HASH', 'DNS_CSR_HASH']
    type: str

  certificate_id:
    description:
      - ZeroSSL certificate ID
      - Required for validate, download states
      - Optional for other states (will be auto-discovered)
    type: str

  certificate_path:
    description:
      - Path to save the certificate file
      - Required for download and present states
      - Directory will be created if it doesn't exist
    type: path

  private_key_path:
    description:
      - Path to save the private key file
      - If not provided, private key is included in certificate_path
    type: path

  ca_bundle_path:
    description:
      - Path to save the CA bundle file
      - If not provided, CA bundle is included in certificate_path
    type: path

  full_chain_path:
    description:
      - Path to save the full certificate chain
      - Includes certificate + CA bundle for web servers
    type: path

  csr_path:
    description:
      - Path to existing Certificate Signing Request (CSR) file
      - Required for request and present states if csr is not provided
      - Must be in PEM format
    type: path

  csr:
    description:
      - CSR content in PEM format
      - Alternative to csr_path
      - Must include all domains in the Subject Alternative Names
    type: str

  web_root:
    description:
      - Web server document root for HTTP validation
      - Required for HTTP_CSR_HASH validation method
      - Validation files will be placed in .well-known/pki-validation/
    type: path

  validity_days:
    description:
      - Certificate validity period in days
      - ZeroSSL supports 90 or 365 days
    default: 90
    choices: [90, 365]
    type: int

  renew_threshold_days:
    description:
      - Days before expiration to trigger renewal
      - Used with check_renew_or_create and present states
    default: 30
    type: int

  force:
    description:
      - Force certificate recreation even if valid certificate exists
      - Useful for testing or when certificate parameters change
    default: false
    type: bool

  backup:
    description:
      - Create backup of existing certificate files before replacement
      - Backup files have .bak extension with timestamp
    default: false
    type: bool

  timeout:
    description:
      - HTTP request timeout in seconds
      - Applied to all API calls
    default: 30
    type: int

  validation_timeout:
    description:
      - Maximum time to wait for certificate validation in seconds
      - Only applies to present state with automatic validation
    default: 300
    type: int

  file_mode:
    description:
      - File permissions for created certificate files
      - Specified as octal string (e.g., '0600')
    default: '0600'
    type: str

notes:
  - Requires Python cryptography library for CSR generation
  - HTTP validation requires web server access for file placement
  - DNS validation requires manual DNS record creation
  - API rate limits are automatically handled with retry logic
  - Wildcard certificates require DNS validation method

seealso:
  - name: ZeroSSL API Documentation
    description: Official ZeroSSL API reference
    link: https://zerossl.com/documentation/api/
  - name: Certificate Authority Authorization (CAA)
    description: DNS CAA records for certificate authority authorization
    link: https://tools.ietf.org/html/rfc6844

requirements:
  - python >= 3.12
  - requests
  - cryptography
  - dnspython (for DNS validation verification)
"""

EXAMPLES = r"""
- name: Create and deploy certificate with automatic validation
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - example.com
      - www.example.com
    csr_path: /etc/ssl/certs/example.com.csr
    certificate_path: /etc/ssl/certs/example.com.crt
    web_root: /var/www/html
    state: present
  register: cert_result

- name: Request certificate and handle validation manually
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - blog.example.com
    csr_path: /etc/ssl/certs/blog.csr
    state: request
  register: cert_request

- name: Place validation files for HTTP-01 challenge
  copy:
    content: "{{ item.content }}"
    dest: "{{ item.file_path }}"
    mode: '0644'
  loop: "{{ cert_request.validation_files }}"
  when: cert_request.validation_files is defined

- name: Validate certificate after placing validation files
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    certificate_id: "{{ cert_request.certificate_id }}"
    state: validate

- name: Download issued certificate
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    certificate_id: "{{ cert_request.certificate_id }}"
    certificate_path: /etc/ssl/certs/blog.crt
    private_key_path: /etc/ssl/private/blog.key
    ca_bundle_path: /etc/ssl/certs/blog-ca.crt
    state: download

- name: Check if certificate needs renewal
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - api.example.com
    state: check_renew_or_create
    renew_threshold_days: 30
  register: renewal_check

- name: Renew certificate if needed
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - api.example.com
    csr_path: /etc/ssl/certs/api.csr
    certificate_path: /etc/ssl/certs/api.crt
    web_root: /var/www/html
    state: present
    force: true
  when: renewal_check.needs_renewal

- name: Create wildcard certificate with DNS validation
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - "*.example.com"
      - example.com
    csr_path: /etc/ssl/certs/wildcard.csr
    state: request
    validation_method: DNS_CSR_HASH
  register: dns_cert

- name: Display required DNS records
  debug:
    msg: |
      Add TXT record for {{ item.domain }}:
      Name: {{ item.record_name }}
      Value: {{ item.record_value }}
  loop: "{{ dns_cert.dns_records }}"
  when: dns_cert.dns_records is defined

- name: Multi-domain (SAN) certificate
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - shop.example.com
      - checkout.example.com
      - payment.example.com
    csr_path: /etc/ssl/certs/shop-san.csr
    certificate_path: /etc/ssl/certs/shop-san.crt
    web_root: /var/www/html
    state: present
    validity_days: 365

- name: Cancel certificate
  zerossl_certificate:
    api_key: "{{ zerossl_api_key }}"
    domains:
      - old.example.com
    state: absent
"""

RETURN = r"""
certificate_id:
  description: ZeroSSL certificate ID
  returned: always (except for absent state)
  type: str
  sample: "abc123def456"

changed:
  description: Whether any changes were made
  returned: always
  type: bool
  sample: true

status:
  description: Certificate status
  returned: when certificate exists
  type: str
  sample: "issued"

domains:
  description: List of domains covered by the certificate
  returned: when certificate exists
  type: list
  elements: str
  sample: ["example.com", "www.example.com"]

expires:
  description: Certificate expiration date
  returned: when certificate exists
  type: str
  sample: "2025-12-17 12:00:00"

days_until_expiry:
  description: Days until certificate expires
  returned: when certificate exists
  type: int
  sample: 87

needs_renewal:
  description: Whether certificate needs renewal
  returned: for check_renew_or_create state
  type: bool
  sample: false

validation_files:
  description: Files to create for HTTP-01 validation
  returned: for request state with HTTP validation
  type: list
  elements: dict
  sample:
    - domain: "example.com"
      filename: "auth123.txt"
      content: "validation_token_content"
      file_path: "/var/www/html/.well-known/pki-validation/auth123.txt"

dns_records:
  description: DNS records to create for DNS-01 validation
  returned: for request state with DNS validation
  type: list
  elements: dict
  sample:
    - domain: "example.com"
      record_name: "_acme-challenge.example.com"
      record_type: "TXT"
      record_value: "dns_challenge_token"

validation_result:
  description: Result of certificate validation
  returned: for validate state
  type: dict
  sample:
    success: true
    validation_completed: true

files_created:
  description: Certificate files that were created or updated
  returned: for download and present states
  type: list
  elements: str
  sample:
    - "/etc/ssl/certs/example.com.crt"
    - "/etc/ssl/private/example.key"

backup_files:
  description: Backup files created when backup=true
  returned: when backup=true and files were backed up
  type: list
  elements: str
  sample:
    - "/etc/ssl/certs/example.com.crt.bak.20250918-143022"

msg:
  description: Human readable message about the operation
  returned: always
  type: str
  sample: "Certificate created and validated successfully"

error_type:
  description: Type of error that occurred
  returned: when failed=true
  type: str
  choices: ['configuration', 'http', 'validation', 'certificate', 'filesystem']
  sample: "validation"

retryable:
  description: Whether the error is retryable
  returned: when failed=true
  type: bool
  sample: true
"""

from ansible.plugins.action import ActionBase
from ansible.module_utils.common.text.converters import to_text
from ansible.errors import AnsibleActionFail
from ansible.utils.display import Display

# Import our custom module_utils components
try:
    # Try importing from ansible.module_utils first (production)
    from ansible.module_utils.zerossl import (
        ZeroSSLAPIClient,
        CertificateManager,
        ValidationHandler,
        ConfigValidator,
        ZeroSSLException,
        ZeroSSLHTTPError,
        ZeroSSLValidationError,
        ZeroSSLCertificateError,
        ZeroSSLConfigurationError,
        ZeroSSLFileSystemError,
        format_exception_for_ansible,
        generate_csr,
        create_file_with_permissions,
    )
    from ansible.module_utils.zerossl.cache import CertificateCacheManager
    from ansible.module_utils.zerossl.concurrency import (
        acquire_certificate_lock,
        acquire_domain_lock,
        acquire_multi_domain_lock,
        safe_write_file,
        get_concurrency_manager,
    )
except ImportError:
    # Fall back to local imports for development/testing
    try:
        import sys
        import os

        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

        from module_utils.zerossl import (
            ZeroSSLAPIClient,
            CertificateManager,
            ValidationHandler,
            ConfigValidator,
            ZeroSSLException,
            ZeroSSLHTTPError,
            ZeroSSLValidationError,
            ZeroSSLCertificateError,
            ZeroSSLConfigurationError,
            ZeroSSLFileSystemError,
            format_exception_for_ansible,
            generate_csr,
            create_file_with_permissions,
        )
        from module_utils.zerossl.cache import CertificateCacheManager
        from module_utils.zerossl.concurrency import (
            acquire_certificate_lock,
            acquire_domain_lock,
            acquire_multi_domain_lock,
            safe_write_file,
            get_concurrency_manager,
        )
    except ImportError as e:
        raise AnsibleActionFail(f"Failed to import ZeroSSL module_utils: {e}")

from pathlib import Path
import os
import json
from datetime import datetime


class ActionModule(ActionBase):
    """
    Ansible action plugin for ZeroSSL certificate management.

    This plugin provides comprehensive SSL certificate lifecycle management
    through the ZeroSSL API, including creation, validation, renewal, and deployment.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.display = Display()
        self.cache_manager = None
        self.concurrency_manager = None

    def run(self, tmp=None, task_vars=None):
        """Main entry point for the action plugin."""
        if task_vars is None:
            task_vars = dict()

        result = super(ActionModule, self).run(tmp, task_vars)

        # Get task arguments
        module_args = self._task.args.copy()

        # Initialize result structure
        result.update(
            {
                "changed": False,
                "certificate_id": None,
                "status": None,
                "domains": None,
                "msg": "No operation performed",
            }
        )

        try:
            # Validate parameters
            self.display.vvv("ZeroSSL: Validating parameters")
            validated_params = self._validate_parameters(module_args)

            # Initialize caching and concurrency
            self._initialize_components(validated_params)

            # Create components
            api_client = self._create_api_client(validated_params)
            cert_manager = self._create_certificate_manager(api_client)
            validation_handler = self._create_validation_handler()

            # Execute the requested operation
            self.display.vv(f"ZeroSSL: Executing state '{validated_params['state']}'")
            operation_result = self._execute_operation(
                validated_params, api_client, cert_manager, validation_handler, task_vars
            )

            # Merge operation result with base result
            result.update(operation_result)

            return result

        except ZeroSSLException as e:
            self.display.warning(f"ZeroSSL operation failed: {e}")
            error_result = format_exception_for_ansible(e)
            result.update(error_result)
            return result

        except Exception as e:
            self.display.error(f"Unexpected error in ZeroSSL plugin: {e}")
            raise AnsibleActionFail(f"ZeroSSL plugin error: {e}")

    def _validate_parameters(self, module_args):
        """Validate and normalize plugin parameters."""
        try:
            validator = ConfigValidator()
            return validator.validate_plugin_parameters(module_args)
        except ZeroSSLConfigurationError as e:
            self.display.error(f"Parameter validation failed: {e}")
            raise

    def _initialize_components(self, params):
        """Initialize caching and concurrency components."""
        # Initialize cache manager if caching is enabled
        if params.get("enable_caching", True):
            self.cache_manager = CertificateCacheManager()
            self.display.vv("ZeroSSL: Certificate caching enabled")

        # Initialize concurrency manager
        self.concurrency_manager = get_concurrency_manager()
        self.display.vv("ZeroSSL: Concurrency management enabled")

    def _create_api_client(self, params):
        """Create ZeroSSL API client with validated parameters."""
        return ZeroSSLAPIClient(api_key=params["api_key"], timeout=params["timeout"])

    def _create_certificate_manager(self, api_client):
        """Create certificate manager with API client and caching."""
        return CertificateManager(
            api_key=api_client.api_key,
            api_client=api_client,
            enable_caching=self.cache_manager is not None,
        )

    def _create_validation_handler(self):
        """Create validation handler for domain validation."""
        return ValidationHandler()

    def _execute_operation(self, params, api_client, cert_manager, validation_handler, task_vars):
        """Execute the requested certificate operation."""
        state = params["state"]

        if state == "present":
            return self._handle_present_state(params, cert_manager, validation_handler, task_vars)
        elif state == "request":
            return self._handle_request_state(params, cert_manager, validation_handler)
        elif state == "validate":
            return self._handle_validate_state(params, cert_manager)
        elif state == "download":
            return self._handle_download_state(params, cert_manager)
        elif state == "check_renew_or_create":
            return self._handle_check_renewal_state(params, cert_manager)
        elif state == "absent":
            return self._handle_absent_state(params, cert_manager)
        else:
            raise ZeroSSLConfigurationError(f"Unsupported state: {state}")

    def _handle_present_state(self, params, cert_manager, validation_handler, task_vars):
        """Handle present state - ensure certificate exists and is valid."""
        # Use multi-domain lock to prevent concurrent operations on same domains
        with acquire_multi_domain_lock(params["domains"], "certificate_present"):
            return self._handle_present_state_locked(
                params, cert_manager, validation_handler, task_vars
            )

    def _handle_present_state_locked(self, params, cert_manager, validation_handler, task_vars):
        """Handle present state with domain locks acquired."""
        result = {"changed": False, "msg": "Certificate already exists and is valid"}

        # Check if certificate already exists and is valid
        if not params.get("force", False):
            needs_renewal = cert_manager.needs_renewal(
                params["domains"], params["renew_threshold_days"]
            )

            if not needs_renewal:
                # Certificate is valid, check if files need updating
                cert_id = cert_manager.find_certificate_for_domains(params["domains"])
                if cert_id:
                    cert_info = cert_manager.get_certificate_status(cert_id)

                    # Check if certificate files need to be updated
                    files_need_update = self._check_certificate_files_need_update(
                        cert_id, cert_manager, params
                    )

                    if not files_need_update:
                        result.update(
                            {
                                "certificate_id": cert_id,
                                "status": cert_info["status"],
                                "domains": params["domains"],
                                "expires": cert_info.get("expires"),
                                "msg": f"Certificate valid until {cert_info.get('expires')}",
                            }
                        )
                        return result
                    else:
                        # Certificate is valid but files need updating
                        if cert_info["status"] == "issued":
                            bundle = cert_manager.download_certificate(cert_id)
                            files_created = self._save_certificate_bundle(bundle, params)
                            result.update(
                                {
                                    "changed": True,
                                    "certificate_id": cert_id,
                                    "status": cert_info["status"],
                                    "domains": params["domains"],
                                    "expires": cert_info.get("expires"),
                                    "files_created": files_created,
                                    "msg": "Certificate files updated",
                                }
                            )
                            return result
                        else:
                            # Certificate exists but not yet issued, continue with normal flow
                            self.display.vv(
                                f"Certificate {cert_id} not yet issued (status: {cert_info['status']}), continuing with certificate creation flow"
                            )
                            # Fall through to certificate creation logic below

        # Need to create/renew certificate
        csr_content = self._get_csr_content(params)

        # Create certificate
        create_result = cert_manager.create_certificate(
            domains=params["domains"],
            csr=csr_content,
            validation_method=params["validation_method"],
            validity_days=params["validity_days"],
        )

        result.update(
            {
                "changed": True,
                "certificate_id": create_result["certificate_id"],
                "status": create_result["status"],
                "domains": create_result["domains"],
            }
        )

        # Handle validation based on method
        if params["validation_method"] == "HTTP_CSR_HASH":
            # Place validation files and validate
            if create_result.get("validation_files"):
                self._place_validation_files(create_result["validation_files"], params["web_root"])

                # Validate certificate
                validate_result = cert_manager.validate_certificate(
                    create_result["certificate_id"], params["validation_method"]
                )
                result["validation_result"] = validate_result

                # Wait for validation and download
                cert_manager.poll_validation_status(
                    create_result["certificate_id"], max_attempts=params["validation_timeout"] // 10
                )

                # Download certificate
                bundle = cert_manager.download_certificate(create_result["certificate_id"])
                files_created = self._save_certificate_bundle(bundle, params)
                result["files_created"] = files_created
                result["msg"] = "Certificate created, validated, and downloaded successfully"

        elif params["validation_method"] == "DNS_CSR_HASH":
            # Return DNS records for manual setup
            result["dns_records"] = create_result.get("dns_records", [])
            result["msg"] = "Certificate created. Complete DNS validation manually."

        return result

    def _handle_request_state(self, params, cert_manager, validation_handler):
        """Handle request state - create certificate and return validation info."""
        # Use multi-domain lock to prevent concurrent requests for same domains
        with acquire_multi_domain_lock(params["domains"], "certificate_request"):
            csr_content = self._get_csr_content(params)

            create_result = cert_manager.create_certificate(
                domains=params["domains"],
                csr=csr_content,
                validation_method=params["validation_method"],
                validity_days=params["validity_days"],
            )

            result = {
                "changed": True,
                "certificate_id": create_result["certificate_id"],
                "status": create_result["status"],
                "domains": create_result["domains"],
                "msg": "Certificate request created successfully",
            }

            # Add validation information
            if params["validation_method"] == "HTTP_CSR_HASH":
                result["validation_files"] = self._prepare_validation_file_paths(
                    create_result.get("validation_files", []), params.get("web_root")
                )
            elif params["validation_method"] == "DNS_CSR_HASH":
                result["dns_records"] = create_result.get("dns_records", [])

            return result

    def _handle_validate_state(self, params, cert_manager):
        """Handle validate state - validate a pending certificate."""
        certificate_id = params.get("certificate_id")

        # Use certificate lock to prevent concurrent validation operations
        with acquire_certificate_lock(certificate_id, "certificate_validate"):
            if not certificate_id:
                # Try to find certificate ID by domains
                certificate_id = cert_manager.find_certificate_for_domains(params["domains"])
                if not certificate_id:
                    raise ZeroSSLCertificateError("Certificate ID not found for specified domains")

            validate_result = cert_manager.validate_certificate(
                certificate_id, params["validation_method"]
            )

            return {
                "changed": True,
                "certificate_id": certificate_id,
                "validation_result": validate_result,
                "msg": "Certificate validation triggered successfully",
            }

    def _handle_download_state(self, params, cert_manager):
        """Handle download state - download an issued certificate."""
        certificate_id = params.get("certificate_id")

        # Use certificate lock to prevent concurrent download operations
        with acquire_certificate_lock(certificate_id, "certificate_download"):
            if not certificate_id:
                # Try to find certificate ID by domains
                certificate_id = cert_manager.find_certificate_for_domains(params["domains"])
                if not certificate_id:
                    raise ZeroSSLCertificateError("Certificate ID not found for specified domains")

            # Check certificate status
            cert_info = cert_manager.get_certificate_status(certificate_id)
            if cert_info["status"] != "issued":
                raise ZeroSSLCertificateError(
                    f"Certificate not ready for download. Status: {cert_info['status']}"
                )

            # Check if files need updating (idempotent behavior)
            files_need_update = self._check_certificate_files_need_update(
                certificate_id, cert_manager, params
            )

            if not files_need_update:
                return {
                    "changed": False,
                    "certificate_id": certificate_id,
                    "status": cert_info["status"],
                    "domains": params["domains"],
                    "expires": cert_info.get("expires"),
                    "msg": "Certificate files already up to date",
                }

            # Download certificate and update files
            bundle = cert_manager.download_certificate(certificate_id)
            files_created = self._save_certificate_bundle(bundle, params)

            return {
                "changed": True,
                "certificate_id": certificate_id,
                "status": cert_info["status"],
                "domains": params["domains"],
                "expires": cert_info.get("expires"),
                "files_created": files_created,
                "msg": "Certificate downloaded successfully",
            }

    def _handle_check_renewal_state(self, params, cert_manager):
        """Handle check_renew_or_create state - check if renewal is needed."""
        needs_renewal = cert_manager.needs_renewal(
            params["domains"], params["renew_threshold_days"]
        )

        result = {"changed": False, "needs_renewal": needs_renewal, "domains": params["domains"]}

        # Get certificate info if it exists
        cert_id = cert_manager.find_certificate_for_domains(params["domains"])
        if cert_id:
            cert_info = cert_manager.get_certificate_status(cert_id)
            result.update(
                {
                    "certificate_id": cert_id,
                    "status": cert_info["status"],
                    "expires": cert_info.get("expires"),
                    "msg": f"Certificate {'needs' if needs_renewal else 'does not need'} renewal",
                }
            )
        else:
            result["msg"] = "No certificate found for domains - creation needed"

        return result

    def _handle_absent_state(self, params, cert_manager):
        """Handle absent state - cancel/remove certificate."""
        cert_id = cert_manager.find_certificate_for_domains(params["domains"])

        if not cert_id:
            return {"changed": False, "msg": "Certificate not found - already absent"}

        # Cancel certificate (ZeroSSL doesn't actually delete, just cancels)
        try:
            cert_manager.api_client.cancel_certificate(cert_id)
            return {
                "changed": True,
                "certificate_id": cert_id,
                "msg": "Certificate cancelled successfully",
            }
        except Exception as e:
            self.display.warning(f"Certificate cancellation may have failed: {e}")
            return {
                "changed": True,
                "certificate_id": cert_id,
                "msg": "Certificate cancellation attempted",
            }

    def _get_csr_content(self, params):
        """Get CSR content from file or parameter."""
        if params.get("csr"):
            return params["csr"]
        elif params.get("csr_path"):
            try:
                with open(params["csr_path"], "r") as f:
                    return f.read()
            except Exception as e:
                raise ZeroSSLFileSystemError(
                    f"Failed to read CSR from {params['csr_path']}: {e}",
                    file_path=params["csr_path"],
                    operation="read",
                )
        else:
            # Generate CSR if neither provided
            self.display.vv("ZeroSSL: Generating CSR for domains")
            csr_content, _ = generate_csr(params["domains"])
            return csr_content

    def _place_validation_files(self, validation_files, web_root):
        """Place HTTP validation files in web root."""
        if not web_root:
            raise ZeroSSLConfigurationError("web_root required for HTTP validation")

        validation_handler = ValidationHandler()
        result = validation_handler.place_validation_files(validation_files, web_root)

        if not result["success"]:
            raise ZeroSSLFileSystemError(
                f"Failed to place validation files: {result['error']}",
                operation="validation_file_placement",
            )

    def _prepare_validation_file_paths(self, validation_files, web_root):
        """Prepare validation file paths for return to user."""
        if not web_root or not validation_files:
            return validation_files

        # Add full file paths for user convenience
        for vf in validation_files:
            if "url_path" in vf and web_root:
                vf["file_path"] = str(Path(web_root) / vf["url_path"].lstrip("/"))

        return validation_files

    def _save_certificate_bundle(self, bundle, params):
        """Save certificate bundle to specified file paths."""
        files_created = []

        # Backup existing files if requested
        if params.get("backup", False):
            backup_files = self._backup_existing_files(params)
            if backup_files:
                files_created.extend(backup_files)

        file_mode = params["file_mode"]  # octal string to int in the plugin params validators.

        # Save certificate
        if params.get("certificate_path"):
            if params.get("private_key_path") or params.get("ca_bundle_path"):
                # Save certificate only
                safe_write_file(
                    params["certificate_path"], bundle["certificate"], mode=file_mode, backup=True
                )
            else:
                # Save full chain (certificate + CA bundle + private key if no separate paths)
                content = bundle["full_chain"]
                if not params.get("private_key_path"):
                    content += "\n" + bundle.get("private_key", "")

                safe_write_file(params["certificate_path"], content, mode=file_mode, backup=True)
            files_created.append(params["certificate_path"])

        # Save private key separately if requested
        if params.get("private_key_path") and bundle.get("private_key"):
            safe_write_file(
                params["private_key_path"],
                bundle["private_key"],
                mode=0o600,  # Always 600 for private keys
                backup=True,
            )
            files_created.append(params["private_key_path"])

        # Save CA bundle separately if requested
        if params.get("ca_bundle_path"):
            safe_write_file(
                params["ca_bundle_path"], bundle["ca_bundle"], mode=file_mode, backup=True
            )
            files_created.append(params["ca_bundle_path"])

        # Save full chain separately if requested
        if params.get("full_chain_path"):
            safe_write_file(
                params["full_chain_path"], bundle["full_chain"], mode=file_mode, backup=True
            )
            files_created.append(params["full_chain_path"])

        return files_created

    def _check_certificate_files_need_update(self, certificate_id, cert_manager, params):
        """
        Check if certificate files need to be updated.

        Returns True if any of the following conditions are met:
        - Certificate files don't exist at specified paths
        - Files exist but are outdated (different content)
        - Force update is requested
        """
        if params.get("force", False):
            return True

        # If no file paths specified, no files to update
        if not any(
            [
                params.get("certificate_path"),
                params.get("private_key_path"),
                params.get("ca_bundle_path"),
                params.get("full_chain_path"),
            ]
        ):
            return False

        try:
            # First check certificate status - only download if issued
            cert_info = cert_manager.get_certificate_status(certificate_id)
            if cert_info["status"] != "issued":
                # Certificate is not issued yet, files definitely need update when it becomes available
                return True

            # Download current certificate to compare
            bundle = cert_manager.download_certificate(certificate_id)

            # Check each file path that was specified
            files_to_check = [
                (params.get("certificate_path"), bundle.get("certificate", "")),
                (params.get("private_key_path"), bundle.get("private_key", "")),
                (params.get("ca_bundle_path"), bundle.get("ca_bundle", "")),
                (params.get("full_chain_path"), bundle.get("full_chain", "")),
            ]

            for file_path, expected_content in files_to_check:
                if file_path and expected_content:
                    if not self._file_matches_content(file_path, expected_content):
                        return True

            return False

        except Exception as e:
            self.display.vv(f"Error checking certificate files, assuming update needed: {e}")
            return True

    def _file_matches_content(self, file_path, expected_content):
        """Check if file exists and matches expected content."""
        try:
            from pathlib import Path

            file_obj = Path(file_path)

            if not file_obj.exists():
                return False

            with open(file_path, "r", encoding="utf-8") as f:
                current_content = f.read().strip()

            # Compare normalized content (strip whitespace)
            return current_content == expected_content.strip()

        except Exception:
            # If we can't read the file, assume it needs updating
            return False

    def _backup_existing_files(self, params):
        """Create backup copies of existing certificate files."""
        backup_files = []
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        file_paths = [
            params.get("certificate_path"),
            params.get("private_key_path"),
            params.get("ca_bundle_path"),
            params.get("full_chain_path"),
        ]

        for file_path in file_paths:
            if file_path and os.path.exists(file_path):
                backup_path = f"{file_path}.bak.{timestamp}"
                try:
                    import shutil

                    shutil.copy2(file_path, backup_path)
                    backup_files.append(backup_path)
                    self.display.vv(f"ZeroSSL: Created backup {backup_path}")
                except Exception as e:
                    self.display.warning(f"Failed to backup {file_path}: {e}")

        return backup_files

    def _get_certificate_id(self, domain):
        """
        Get certificate ID for a specific domain.

        This is a helper method used by integration tests to check for
        existing certificates for test domains.

        Args:
            domain: Domain name to search for

        Returns:
            Certificate ID if found, None otherwise
        """
        try:
            # Create a temporary API client for the lookup
            # Note: This assumes api_key is available in task args
            if hasattr(self, "_task") and self._task.args.get("api_key"):
                api_client = ZeroSSLAPIClient(self._task.args["api_key"])
                cert_manager = CertificateManager(
                    api_key=self._task.args["api_key"], api_client=api_client
                )

                # Find certificate for the domain
                return cert_manager.find_certificate_for_domains([domain])
            else:
                self.display.warning("No API key available for certificate lookup")
                return None

        except Exception as e:
            self.display.vv(f"Error looking up certificate for {domain}: {e}")
            return None

    def _get_certificate_info(self, certificate_id):
        """
        Get certificate information by ID.

        This is a helper method used by integration tests to retrieve
        certificate details.

        Args:
            certificate_id: ZeroSSL certificate ID

        Returns:
            Certificate information dict
        """
        try:
            # Create a temporary API client for the lookup
            if hasattr(self, "_task") and self._task.args.get("api_key"):
                api_client = ZeroSSLAPIClient(self._task.args["api_key"])
                cert_manager = CertificateManager(
                    api_key=self._task.args["api_key"], api_client=api_client
                )

                # Get certificate status
                return cert_manager.get_certificate_status(certificate_id)
            else:
                self.display.warning("No API key available for certificate lookup")
                return None

        except Exception as e:
            self.display.vv(f"Error getting certificate info for {certificate_id}: {e}")
            return None
