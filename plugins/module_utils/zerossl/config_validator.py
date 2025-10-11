# -*- coding: utf-8 -*-
"""
ZeroSSL Configuration Validator.

This module provides comprehensive validation for Ansible plugin parameters
and configuration options, ensuring all inputs are properly validated before
use in certificate operations.
"""

from typing import Dict, Any, List, Optional, Union
from pathlib import Path

from .exceptions import ZeroSSLConfigurationError
from .models import OperationState, ValidationMethod
from .utils import validate_api_key, validate_domains, validate_file_path


class ConfigValidator:
    """
    Configuration validator for ZeroSSL plugin parameters.

    This class provides comprehensive validation for all plugin parameters,
    ensuring they meet requirements and are compatible with each other.
    """

    def __init__(self):
        """Initialize the configuration validator."""
        # Define valid parameter ranges and options
        self.valid_states = [state.value for state in OperationState]
        self.valid_validation_methods = [method.value for method in ValidationMethod]
        self.valid_validity_days = [90, 365]

    def validate_plugin_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate all plugin parameters.

        Args:
            params: Dictionary of plugin parameters

        Returns:
            Validated and normalized parameters

        Raises:
            ZeroSSLConfigurationError: If any parameter is invalid
        """
        validated_params = {}

        # Required parameters
        validated_params["api_key"] = self._validate_api_key(params.get("api_key"))
        validated_params["domains"] = self._validate_domains(params.get("domains"))

        # Optional parameters with defaults
        validated_params["state"] = self._validate_state(params.get("state", "present"))
        validated_params["validation_method"] = self._validate_validation_method(
            params.get("validation_method", "HTTP_CSR_HASH")
        )
        validated_params["validity_days"] = self._validate_validity_days(
            params.get("validity_days", 90)
        )
        validated_params["renew_threshold_days"] = self._validate_renew_threshold_days(
            params.get("renew_threshold_days", 30)
        )

        # File paths (optional)
        if params.get("certificate_path"):
            validated_params["certificate_path"] = self._validate_certificate_path(
                params["certificate_path"]
            )

        if params.get("private_key_path"):
            validated_params["private_key_path"] = self._validate_private_key_path(
                params["private_key_path"]
            )

        if params.get("ca_bundle_path"):
            validated_params["ca_bundle_path"] = self._validate_ca_bundle_path(
                params["ca_bundle_path"]
            )

        if params.get("full_chain_path"):
            validated_params["full_chain_path"] = self._validate_full_chain_path(
                params["full_chain_path"]
            )

        if params.get("csr_path"):
            validated_params["csr_path"] = self._validate_csr_path(params["csr_path"])

        if params.get("web_root"):
            validated_params["web_root"] = self._validate_web_root(params["web_root"])

        # CSR content (optional, can be generated)
        if params.get("csr"):
            validated_params["csr"] = self._validate_csr_content(params["csr"])

        # Advanced options
        validated_params["force"] = self._validate_boolean(params.get("force", False), "force")
        validated_params["backup"] = self._validate_boolean(params.get("backup", False), "backup")

        # Timeout settings
        validated_params["timeout"] = self._validate_timeout(params.get("timeout", 30))
        validated_params["validation_timeout"] = self._validate_validation_timeout(
            params.get("validation_timeout", 300)
        )

        # File permissions
        validated_params["file_mode"] = self._validate_file_mode(params.get("file_mode", "0600"))

        # Validate parameter compatibility
        self._validate_parameter_compatibility(validated_params)

        return validated_params

    def _validate_api_key(self, api_key: Any) -> str:
        """Validate API key parameter."""
        if not api_key:
            raise ZeroSSLConfigurationError("api_key is required", parameter="api_key")

        if not isinstance(api_key, str):
            raise ZeroSSLConfigurationError(
                "api_key must be a string", parameter="api_key", parameter_value=str(type(api_key))
            )

        return validate_api_key(api_key)

    def _validate_domains(self, domains: Any) -> List[str]:
        """Validate domains parameter."""
        if not domains:
            raise ZeroSSLConfigurationError("domains is required", parameter="domains")

        if isinstance(domains, str):
            # Convert single domain string to list
            domains = [domains]
        elif not isinstance(domains, list):
            raise ZeroSSLConfigurationError(
                "domains must be a string or list of strings",
                parameter="domains",
                parameter_value=str(type(domains)),
            )

        # Validate each domain
        return validate_domains(domains)

    def _validate_state(self, state: Any) -> str:
        """Validate state parameter."""
        if not isinstance(state, str):
            raise ZeroSSLConfigurationError(
                "state must be a string", parameter="state", parameter_value=str(type(state))
            )

        if state not in self.valid_states:
            raise ZeroSSLConfigurationError(
                f"Invalid state: {state}",
                parameter="state",
                parameter_value=state,
                expected_format=f"One of: {', '.join(self.valid_states)}",
            )

        return state

    def _validate_validation_method(self, validation_method: Any) -> str:
        """Validate validation_method parameter."""
        if not isinstance(validation_method, str):
            raise ZeroSSLConfigurationError(
                "validation_method must be a string",
                parameter="validation_method",
                parameter_value=str(type(validation_method)),
            )

        if validation_method not in self.valid_validation_methods:
            raise ZeroSSLConfigurationError(
                f"Invalid validation_method: {validation_method}",
                parameter="validation_method",
                parameter_value=validation_method,
                expected_format=f"One of: {', '.join(self.valid_validation_methods)}",
            )

        return validation_method

    def _validate_validity_days(self, validity_days: Any) -> int:
        """Validate validity_days parameter."""
        if isinstance(validity_days, str):
            try:
                validity_days = int(validity_days)
            except ValueError:
                raise ZeroSSLConfigurationError(
                    "validity_days must be an integer",
                    parameter="validity_days",
                    parameter_value=str(validity_days),
                )

        if not isinstance(validity_days, int):
            raise ZeroSSLConfigurationError(
                "validity_days must be an integer",
                parameter="validity_days",
                parameter_value=str(type(validity_days)),
            )

        if validity_days not in self.valid_validity_days:
            raise ZeroSSLConfigurationError(
                f"Invalid validity_days: {validity_days}",
                parameter="validity_days",
                parameter_value=str(validity_days),
                expected_format=f"One of: {', '.join(map(str, self.valid_validity_days))}",
            )

        return validity_days

    def _validate_renew_threshold_days(self, renew_threshold_days: Any) -> int:
        """Validate renew_threshold_days parameter."""
        if isinstance(renew_threshold_days, str):
            try:
                renew_threshold_days = int(renew_threshold_days)
            except ValueError:
                raise ZeroSSLConfigurationError(
                    "renew_threshold_days must be an integer",
                    parameter="renew_threshold_days",
                    parameter_value=str(renew_threshold_days),
                )

        if not isinstance(renew_threshold_days, int):
            raise ZeroSSLConfigurationError(
                "renew_threshold_days must be an integer",
                parameter="renew_threshold_days",
                parameter_value=str(type(renew_threshold_days)),
            )

        if not 1 <= renew_threshold_days <= 365:
            raise ZeroSSLConfigurationError(
                f"renew_threshold_days must be between 1 and 365 days: {renew_threshold_days}",
                parameter="renew_threshold_days",
                parameter_value=str(renew_threshold_days),
                expected_format="Integer between 1 and 365",
            )

        return renew_threshold_days

    def _validate_certificate_path(self, certificate_path: Any) -> str:
        """Validate certificate_path parameter."""
        if not isinstance(certificate_path, str):
            raise ZeroSSLConfigurationError(
                "certificate_path must be a string",
                parameter="certificate_path",
                parameter_value=str(type(certificate_path)),
            )

        return validate_file_path(certificate_path, must_be_writable=True)

    def _validate_private_key_path(self, private_key_path: Any) -> str:
        """Validate private_key_path parameter."""
        if not isinstance(private_key_path, str):
            raise ZeroSSLConfigurationError(
                "private_key_path must be a string",
                parameter="private_key_path",
                parameter_value=str(type(private_key_path)),
            )

        return validate_file_path(private_key_path, must_be_writable=True)

    def _validate_ca_bundle_path(self, ca_bundle_path: Any) -> str:
        """Validate ca_bundle_path parameter."""
        if not isinstance(ca_bundle_path, str):
            raise ZeroSSLConfigurationError(
                "ca_bundle_path must be a string",
                parameter="ca_bundle_path",
                parameter_value=str(type(ca_bundle_path)),
            )

        return validate_file_path(ca_bundle_path, must_be_writable=True)

    def _validate_full_chain_path(self, full_chain_path: Any) -> str:
        """Validate full_chain_path parameter."""
        if not isinstance(full_chain_path, str):
            raise ZeroSSLConfigurationError(
                "full_chain_path must be a string",
                parameter="full_chain_path",
                parameter_value=str(type(full_chain_path)),
            )

        return validate_file_path(full_chain_path, must_be_writable=True)

    def _validate_csr_path(self, csr_path: Any) -> str:
        """Validate csr_path parameter."""
        if not isinstance(csr_path, str):
            raise ZeroSSLConfigurationError(
                "csr_path must be a string",
                parameter="csr_path",
                parameter_value=str(type(csr_path)),
            )

        return validate_file_path(csr_path, must_exist=True)

    def _validate_web_root(self, web_root: Any) -> str:
        """Validate web_root parameter."""
        if not isinstance(web_root, str):
            raise ZeroSSLConfigurationError(
                "web_root must be a string",
                parameter="web_root",
                parameter_value=str(type(web_root)),
            )

        return validate_file_path(web_root, must_exist=True, must_be_writable=True)

    def _validate_csr_content(self, csr: Any) -> str:
        """Validate CSR content parameter."""
        if not isinstance(csr, str):
            raise ZeroSSLConfigurationError(
                "csr must be a string", parameter="csr", parameter_value=str(type(csr))
            )

        csr = csr.strip()
        if not csr:
            raise ZeroSSLConfigurationError("csr content cannot be empty", parameter="csr")

        # Basic CSR format validation
        if not (
            "-----BEGIN CERTIFICATE REQUEST-----" in csr
            and "-----END CERTIFICATE REQUEST-----" in csr
        ):
            raise ZeroSSLConfigurationError(
                "csr must be in PEM format",
                parameter="csr",
                expected_format="PEM-formatted certificate request",
            )

        return csr

    def _validate_boolean(self, value: Any, parameter_name: str) -> bool:
        """Validate boolean parameter."""
        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            if value.lower() in ["true", "yes", "1", "on"]:
                return True
            elif value.lower() in ["false", "no", "0", "off"]:
                return False

        raise ZeroSSLConfigurationError(
            f"{parameter_name} must be a boolean",
            parameter=parameter_name,
            parameter_value=str(value),
            expected_format="true, false, yes, no, 1, 0",
        )

    def _validate_timeout(self, timeout: Any) -> int:
        """Validate timeout parameter."""
        if isinstance(timeout, str):
            try:
                timeout = int(timeout)
            except ValueError:
                raise ZeroSSLConfigurationError(
                    "timeout must be an integer", parameter="timeout", parameter_value=str(timeout)
                )

        if not isinstance(timeout, int):
            raise ZeroSSLConfigurationError(
                "timeout must be an integer",
                parameter="timeout",
                parameter_value=str(type(timeout)),
            )

        if not 1 <= timeout <= 300:
            raise ZeroSSLConfigurationError(
                f"timeout must be between 1 and 300 seconds: {timeout}",
                parameter="timeout",
                parameter_value=str(timeout),
                expected_format="Integer between 1 and 300",
            )

        return timeout

    def _validate_validation_timeout(self, validation_timeout: Any) -> int:
        """Validate validation_timeout parameter."""
        if isinstance(validation_timeout, str):
            try:
                validation_timeout = int(validation_timeout)
            except ValueError:
                raise ZeroSSLConfigurationError(
                    "validation_timeout must be an integer",
                    parameter="validation_timeout",
                    parameter_value=str(validation_timeout),
                )

        if not isinstance(validation_timeout, int):
            raise ZeroSSLConfigurationError(
                "validation_timeout must be an integer",
                parameter="validation_timeout",
                parameter_value=str(type(validation_timeout)),
            )

        if not 60 <= validation_timeout <= 3600:
            raise ZeroSSLConfigurationError(
                f"validation_timeout must be between 60 and 3600 seconds: {validation_timeout}",
                parameter="validation_timeout",
                parameter_value=str(validation_timeout),
                expected_format="Integer between 60 and 3600",
            )

        return validation_timeout

    def _validate_file_mode(self, file_mode: Any) -> int:
        """Validate file_mode parameter."""
        if isinstance(file_mode, int):
            mode = file_mode
        elif isinstance(file_mode, str):
            try:
                # Handle octal strings like '0600' or '600'
                if file_mode.startswith("0"):
                    mode = int(file_mode, 8)
                else:
                    mode = int(file_mode, 8)
            except ValueError:
                raise ZeroSSLConfigurationError(
                    "file_mode must be a valid octal number",
                    parameter="file_mode",
                    parameter_value=str(file_mode),
                    expected_format="Octal number like '0600' or '600'",
                )
        else:
            raise ZeroSSLConfigurationError(
                "file_mode must be a string or integer",
                parameter="file_mode",
                parameter_value=str(type(file_mode)),
            )

        # Check if mode is reasonable (between 0000 and 0777)
        if not 0 <= mode <= 0o777:
            raise ZeroSSLConfigurationError(
                f"file_mode must be between 0000 and 0777: {oct(mode)}",
                parameter="file_mode",
                parameter_value=oct(mode),
                expected_format="Octal number between 0000 and 0777",
            )

        return mode

    def _validate_parameter_compatibility(self, params: Dict[str, Any]):
        """Validate that parameter combinations are compatible."""
        # DNS validation is required for wildcard domains
        domains = params["domains"]
        validation_method = params["validation_method"]

        for domain in domains:
            if domain.startswith("*.") and validation_method == "HTTP_CSR_HASH":
                raise ZeroSSLConfigurationError(
                    "Wildcard domains require DNS validation method",
                    parameter="validation_method",
                    parameter_value=validation_method,
                    expected_format="DNS_CSR_HASH for wildcard domains",
                )

        # HTTP validation requires web_root for some states
        if (
            validation_method == "HTTP_CSR_HASH"
            and params["state"] in ["present", "validate"]
            and "web_root" not in params
        ):
            raise ZeroSSLConfigurationError(
                "web_root is required for HTTP validation",
                parameter="web_root",
                expected_format="Path to web server document root",
            )

        # CSR path and CSR content are mutually exclusive
        if "csr_path" in params and "csr" in params:
            raise ZeroSSLConfigurationError("csr_path and csr parameters are mutually exclusive")

        # Validate renewal threshold vs validity period
        if params["renew_threshold_days"] >= params["validity_days"]:
            raise ZeroSSLConfigurationError(
                f"renew_threshold_days ({params['renew_threshold_days']}) must be less than "
                f"validity_days ({params['validity_days']})",
                parameter="renew_threshold_days",
            )

    def validate_file_paths_writable(self, file_paths: List[str]) -> Dict[str, bool]:
        """
        Validate that file paths are writable.

        Args:
            file_paths: List of file paths to check

        Returns:
            Dictionary mapping file paths to writability status
        """
        results = {}

        for file_path in file_paths:
            try:
                validate_file_path(file_path, must_be_writable=True)
                results[file_path] = True
            except ZeroSSLConfigurationError:
                results[file_path] = False

        return results

    def get_parameter_schema(self) -> Dict[str, Any]:
        """
        Get parameter schema for documentation purposes.

        Returns:
            Dictionary describing parameter requirements
        """
        return {
            "required": ["api_key", "domains"],
            "optional": {
                "state": {"type": "str", "default": "present", "choices": self.valid_states},
                "validation_method": {
                    "type": "str",
                    "default": "HTTP_CSR_HASH",
                    "choices": self.valid_validation_methods,
                },
                "validity_days": {
                    "type": "int",
                    "default": 90,
                    "choices": self.valid_validity_days,
                },
                "renew_threshold_days": {"type": "int", "default": 30, "range": [1, 365]},
                "certificate_path": {
                    "type": "path",
                    "description": "Path to save certificate file",
                },
                "private_key_path": {
                    "type": "path",
                    "description": "Path to save private key file",
                },
                "ca_bundle_path": {"type": "path", "description": "Path to save CA bundle file"},
                "full_chain_path": {
                    "type": "path",
                    "description": "Path to save full certificate chain",
                },
                "web_root": {
                    "type": "path",
                    "description": "Web server document root for HTTP validation",
                },
                "csr_path": {"type": "path", "description": "Path to existing CSR file"},
                "csr": {"type": "str", "description": "CSR content in PEM format"},
                "force": {
                    "type": "bool",
                    "default": False,
                    "description": "Force certificate recreation",
                },
                "backup": {
                    "type": "bool",
                    "default": False,
                    "description": "Backup existing certificate files",
                },
                "timeout": {
                    "type": "int",
                    "default": 30,
                    "range": [1, 300],
                    "description": "API request timeout in seconds",
                },
                "validation_timeout": {
                    "type": "int",
                    "default": 300,
                    "range": [60, 3600],
                    "description": "Validation polling timeout in seconds",
                },
                "file_mode": {
                    "type": "str",
                    "default": "0600",
                    "description": "File permissions for certificate files",
                },
            },
        }
