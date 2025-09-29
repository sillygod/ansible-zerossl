# -*- coding: utf-8 -*-
"""
ZeroSSL exception hierarchy.

This module defines custom exceptions used throughout the ZeroSSL plugin
for proper error handling and reporting.
"""

from typing import Optional, Dict, Any


class ZeroSSLException(Exception):
    """
    Base exception for all ZeroSSL plugin errors.

    This is the base class for all exceptions raised by the ZeroSSL plugin.
    It provides common functionality for error reporting and debugging.
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            # Sanitize sensitive data in error messages
            sanitized_details = {}
            for k, v in self.details.items():
                if isinstance(v, dict):
                    # For nested dicts, sanitize known sensitive keys
                    sanitized_v = {}
                    for nested_k, nested_v in v.items():
                        if nested_k.lower() in ('api_key', 'access_key', 'password', 'secret', 'token'):
                            sanitized_v[nested_k] = '***'
                        else:
                            sanitized_v[nested_k] = nested_v
                    sanitized_details[k] = sanitized_v
                elif k.lower() in ('api_key', 'access_key', 'password', 'secret', 'token'):
                    sanitized_details[k] = '***'
                else:
                    sanitized_details[k] = v

            details_str = ", ".join(f"{k}={v}" for k, v in sanitized_details.items())
            return f"{self.message} ({details_str})"
        return self.message

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for structured logging."""
        return {
            'exception_type': self.__class__.__name__,
            'message': self.message,
            'details': self.details
        }


class ZeroSSLHTTPError(ZeroSSLException):
    """
    Exception raised for HTTP-related errors when communicating with ZeroSSL API.

    This includes network timeouts, HTTP status code errors, and API response
    parsing failures.
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_data: Optional[Dict[str, Any]] = None,
        request_url: Optional[str] = None
    ):
        details = {}
        if status_code is not None:
            details['status_code'] = status_code
        if response_data:
            details['response_data'] = response_data
        if request_url:
            details['request_url'] = request_url

        super().__init__(message, details)
        self.status_code = status_code
        self.response_data = response_data or {}
        self.request_url = request_url

    @property
    def is_rate_limited(self) -> bool:
        """Check if the error is due to rate limiting."""
        return self.status_code == 429

    @property
    def is_authentication_error(self) -> bool:
        """Check if the error is due to authentication failure."""
        return self.status_code == 401

    @property
    def is_server_error(self) -> bool:
        """Check if the error is a server-side error."""
        return self.status_code is not None and 500 <= self.status_code < 600

    @property
    def is_client_error(self) -> bool:
        """Check if the error is a client-side error."""
        return self.status_code is not None and 400 <= self.status_code < 500


class ZeroSSLValidationError(ZeroSSLException):
    """
    Exception raised for domain validation errors.

    This includes HTTP-01 validation failures, DNS-01 validation failures,
    and validation timeout errors.
    """

    def __init__(
        self,
        message: str,
        domain: Optional[str] = None,
        validation_method: Optional[str] = None,
        validation_details: Optional[Dict[str, Any]] = None
    ):
        details = {}
        if domain:
            details['domain'] = domain
        if validation_method:
            details['validation_method'] = validation_method
        if validation_details:
            details.update(validation_details)

        super().__init__(message, details)
        self.domain = domain
        self.validation_method = validation_method
        self.validation_details = validation_details or {}

    @property
    def is_http_validation_error(self) -> bool:
        """Check if this is an HTTP validation error."""
        return self.validation_method == "HTTP_CSR_HASH"

    @property
    def is_dns_validation_error(self) -> bool:
        """Check if this is a DNS validation error."""
        return self.validation_method == "DNS_CSR_HASH"


class ZeroSSLCertificateError(ZeroSSLException):
    """
    Exception raised for certificate-related errors.

    This includes certificate creation failures, certificate download errors,
    and certificate processing failures.
    """

    def __init__(
        self,
        message: str,
        certificate_id: Optional[str] = None,
        certificate_status: Optional[str] = None,
        operation: Optional[str] = None
    ):
        details = {}
        if certificate_id:
            details['certificate_id'] = certificate_id
        if certificate_status:
            details['certificate_status'] = certificate_status
        if operation:
            details['operation'] = operation

        super().__init__(message, details)
        self.certificate_id = certificate_id
        self.certificate_status = certificate_status
        self.operation = operation

    @property
    def is_creation_error(self) -> bool:
        """Check if this is a certificate creation error."""
        return self.operation == "create"

    @property
    def is_download_error(self) -> bool:
        """Check if this is a certificate download error."""
        return self.operation == "download"

    @property
    def is_processing_error(self) -> bool:
        """Check if this is a certificate processing error."""
        return self.operation == "process"


class ZeroSSLConfigurationError(ZeroSSLException):
    """
    Exception raised for configuration and parameter validation errors.

    This includes invalid API keys, malformed domains, missing required
    parameters, and incompatible option combinations.
    """

    def __init__(
        self,
        message: str,
        parameter: Optional[str] = None,
        parameter_value: Optional[str] = None,
        expected_format: Optional[str] = None
    ):
        details = {}
        if parameter:
            details['parameter'] = parameter
        if parameter_value:
            details['parameter_value'] = parameter_value
        if expected_format:
            details['expected_format'] = expected_format

        super().__init__(message, details)
        self.parameter = parameter
        self.parameter_value = parameter_value
        self.expected_format = expected_format

    @property
    def is_domain_error(self) -> bool:
        """Check if this is a domain validation error."""
        return self.parameter and 'domain' in self.parameter.lower()

    @property
    def is_api_key_error(self) -> bool:
        """Check if this is an API key validation error."""
        return self.parameter and 'api_key' in self.parameter.lower()


class ZeroSSLRateLimitError(ZeroSSLHTTPError):
    """
    Exception raised when ZeroSSL API rate limits are exceeded.

    This is a specialized HTTP error for rate limiting scenarios.
    """

    def __init__(
        self,
        message: str = "ZeroSSL API rate limit exceeded",
        retry_after: Optional[int] = None,
        limit_reset_time: Optional[str] = None
    ):
        details = {}
        if retry_after is not None:
            details['retry_after'] = retry_after
        if limit_reset_time:
            details['limit_reset_time'] = limit_reset_time

        super().__init__(message, status_code=429, response_data=details)
        self.retry_after = retry_after
        self.limit_reset_time = limit_reset_time


class ZeroSSLTimeoutError(ZeroSSLException):
    """
    Exception raised for timeout-related errors.

    This includes validation polling timeouts, API request timeouts,
    and certificate processing timeouts.
    """

    def __init__(
        self,
        message: str,
        timeout_duration: Optional[int] = None,
        operation: Optional[str] = None
    ):
        details = {}
        if timeout_duration is not None:
            details['timeout_duration'] = timeout_duration
        if operation:
            details['operation'] = operation

        super().__init__(message, details)
        self.timeout_duration = timeout_duration
        self.operation = operation

    @property
    def is_validation_timeout(self) -> bool:
        """Check if this is a validation polling timeout."""
        return self.operation == "validation_polling"

    @property
    def is_api_timeout(self) -> bool:
        """Check if this is an API request timeout."""
        return self.operation == "api_request"


class ZeroSSLFileSystemError(ZeroSSLException):
    """
    Exception raised for filesystem-related errors.

    This includes file permission errors, disk space issues,
    and invalid file paths.
    """

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        operation: Optional[str] = None,
        permissions_needed: Optional[str] = None
    ):
        details = {}
        if file_path:
            details['file_path'] = file_path
        if operation:
            details['operation'] = operation
        if permissions_needed:
            details['permissions_needed'] = permissions_needed

        super().__init__(message, details)
        self.file_path = file_path
        self.operation = operation
        self.permissions_needed = permissions_needed

    @property
    def is_permission_error(self) -> bool:
        """Check if this is a file permission error."""
        return 'permission' in self.message.lower()

    @property
    def is_disk_space_error(self) -> bool:
        """Check if this is a disk space error."""
        return 'space' in self.message.lower() or 'full' in self.message.lower()


class ZeroSSLConcurrencyError(ZeroSSLException):
    """
    Exception raised for concurrency-related errors.

    This includes lock acquisition failures, resource conflicts,
    and thread synchronization issues.
    """

    def __init__(
        self,
        message: str,
        resource_id: Optional[str] = None,
        operation_type: Optional[str] = None,
        timeout_duration: Optional[int] = None
    ):
        details = {}
        if resource_id:
            details['resource_id'] = resource_id
        if operation_type:
            details['operation_type'] = operation_type
        if timeout_duration:
            details['timeout_duration'] = timeout_duration

        super().__init__(message, details)
        self.resource_id = resource_id
        self.operation_type = operation_type
        self.timeout_duration = timeout_duration

    @property
    def is_lock_timeout(self) -> bool:
        """Check if this is a lock acquisition timeout."""
        return 'lock' in self.message.lower() and 'timeout' in self.message.lower()

    @property
    def is_resource_conflict(self) -> bool:
        """Check if this is a resource conflict error."""
        return 'conflict' in self.message.lower() or 'busy' in self.message.lower()


class ZeroSSLSecurityError(ZeroSSLException):
    """
    Exception raised for security-related errors.

    This includes API key exposure, insecure file permissions,
    and cryptographic validation failures.
    """

    def __init__(
        self,
        message: str,
        security_issue: Optional[str] = None,
        recommendation: Optional[str] = None
    ):
        details = {}
        if security_issue:
            details['security_issue'] = security_issue
        if recommendation:
            details['recommendation'] = recommendation

        super().__init__(message, details)
        self.security_issue = security_issue
        self.recommendation = recommendation


def format_exception_for_ansible(exception: ZeroSSLException) -> Dict[str, Any]:
    """
    Format ZeroSSL exception for Ansible module response.

    Args:
        exception: The ZeroSSL exception to format

    Returns:
        Dictionary suitable for Ansible module failure response
    """
    return {
        'msg': str(exception),
        'exception_type': exception.__class__.__name__,
        'exception_details': exception.details,
        'failed': True
    }


def is_retryable_error(exception: ZeroSSLException) -> bool:
    """
    Determine if an exception represents a retryable error.

    Args:
        exception: The exception to check

    Returns:
        True if the error is retryable, False otherwise
    """
    if isinstance(exception, ZeroSSLRateLimitError):
        return True

    if isinstance(exception, ZeroSSLHTTPError):
        # Retry on server errors and some client errors
        if exception.is_server_error:
            return True
        if exception.status_code in [408, 429, 502, 503, 504]:
            return True

    if isinstance(exception, ZeroSSLTimeoutError):
        # Retry API timeouts but not validation timeouts
        return exception.is_api_timeout

    return False


def get_retry_delay(exception: ZeroSSLException, attempt: int) -> int:
    """
    Calculate retry delay for retryable errors.

    Args:
        exception: The exception that occurred
        attempt: The current attempt number (1-based)

    Returns:
        Delay in seconds before next retry
    """
    if isinstance(exception, ZeroSSLRateLimitError) and exception.retry_after:
        return exception.retry_after

    # Exponential backoff with jitter
    base_delay = min(2 ** attempt, 60)  # Max 60 seconds
    return base_delay
