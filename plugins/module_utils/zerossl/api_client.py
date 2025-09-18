# -*- coding: utf-8 -*-
"""
ZeroSSL API client.

This module provides a comprehensive client for interacting with the ZeroSSL API,
including rate limiting, retry logic, and proper error handling.
"""

import time
import requests
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode

from .exceptions import (
    ZeroSSLHTTPError,
    ZeroSSLRateLimitError,
    ZeroSSLConfigurationError,
    is_retryable_error,
    get_retry_delay
)
from .utils import validate_api_key, validate_domains


class ZeroSSLAPIClient:
    """
    ZeroSSL API client with rate limiting and retry logic.

    This client handles all interactions with the ZeroSSL API, including
    certificate creation, validation, and download operations.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.zerossl.com",
        max_retries: int = 3,
        timeout: int = 30,
        rate_limit_remaining: int = 5000
    ):
        """
        Initialize ZeroSSL API client.

        Args:
            api_key: ZeroSSL API access key
            base_url: Base URL for ZeroSSL API
            max_retries: Maximum number of retry attempts
            timeout: Request timeout in seconds
            rate_limit_remaining: Initial rate limit count
        """
        self.api_key = validate_api_key(api_key)
        self.base_url = base_url.rstrip('/')
        self.max_retries = max_retries
        self.timeout = timeout
        self.rate_limit_remaining = rate_limit_remaining

        # Create session for connection pooling
        self.session = requests.Session()
        self.session.headers.update(self._build_headers())

    def _build_headers(self) -> Dict[str, str]:
        """Build default HTTP headers for API requests."""
        return {
            'User-Agent': 'ansible-zerossl-plugin/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def _build_url(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> str:
        """
        Build complete URL for API endpoint.

        Args:
            endpoint: API endpoint path
            params: Query parameters to include

        Returns:
            Complete URL with parameters
        """
        url = f"{self.base_url}{endpoint}"

        # Add authentication parameter
        auth_params = self._add_auth(params or {})

        if auth_params:
            url += '?' + urlencode(auth_params)

        return url

    def _add_auth(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Add authentication parameters to request."""
        auth_params = params.copy()
        auth_params['access_key'] = self.api_key
        return auth_params

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make HTTP request to ZeroSSL API with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            data: Form data for POST requests
            params: Query parameters
            json: JSON data for requests

        Returns:
            API response data

        Raises:
            ZeroSSLHTTPError: If API request fails
            ZeroSSLRateLimitError: If rate limit exceeded
        """
        url = self._build_url(endpoint, params) if method == 'GET' else f"{self.base_url}{endpoint}"

        # Prepare request data
        request_kwargs = {
            'timeout': self.timeout
        }

        if method == 'POST':
            if json:
                request_kwargs['json'] = json
                # Add auth to JSON payload for POST
                if 'access_key' not in request_kwargs['json']:
                    request_kwargs['json']['access_key'] = self.api_key
            elif data:
                # Add auth to form data
                auth_data = data.copy()
                auth_data['access_key'] = self.api_key
                request_kwargs['data'] = auth_data
            else:
                request_kwargs['data'] = {'access_key': self.api_key}
        elif method == 'GET':
            request_kwargs['url'] = url

        # Retry loop
        last_exception = None
        for attempt in range(self.max_retries + 1):
            try:
                # Make the request
                if method == 'GET':
                    response = self.session.get(**request_kwargs)
                elif method == 'POST':
                    response = self.session.post(f"{self.base_url}{endpoint}", **request_kwargs)
                else:
                    raise ZeroSSLHTTPError(f"Unsupported HTTP method: {method}")

                # Update rate limit info from headers
                self._update_rate_limit_from_response(response)

                # Handle response
                if response.status_code == 200 or response.status_code == 201:
                    try:
                        return response.json()
                    except ValueError as e:
                        raise ZeroSSLHTTPError(
                            f"Invalid JSON response: {e}",
                            status_code=response.status_code,
                            response_data={'text': response.text}
                        )

                # Handle error responses
                self._handle_error_response(response, url)

            except requests.RequestException as e:
                last_exception = ZeroSSLHTTPError(f"Request failed: {e}")

                # Don't retry on the last attempt
                if attempt == self.max_retries:
                    break

                # Calculate retry delay
                if is_retryable_error(last_exception):
                    delay = get_retry_delay(last_exception, attempt + 1)
                    time.sleep(delay)
                else:
                    break

        # If we get here, all retries failed
        raise last_exception or ZeroSSLHTTPError("Request failed after all retries")

    def _update_rate_limit_from_response(self, response: requests.Response):
        """Update rate limit information from response headers."""
        if 'X-RateLimit-Remaining' in response.headers:
            try:
                self.rate_limit_remaining = int(response.headers['X-RateLimit-Remaining'])
            except ValueError:
                pass

    def _handle_error_response(self, response: requests.Response, url: str):
        """
        Handle error responses from the API.

        Args:
            response: HTTP response object
            url: Request URL

        Raises:
            ZeroSSLHTTPError: For general HTTP errors
            ZeroSSLRateLimitError: For rate limit errors
        """
        try:
            error_data = response.json()
        except ValueError:
            error_data = {'error': {'message': response.text}}

        error_message = "Unknown error"
        if 'error' in error_data:
            if isinstance(error_data['error'], dict):
                error_message = error_data['error'].get('message', 'Unknown error')
            else:
                error_message = str(error_data['error'])

        # Handle rate limiting
        if response.status_code == 429:
            retry_after = None
            if 'Retry-After' in response.headers:
                try:
                    retry_after = int(response.headers['Retry-After'])
                except ValueError:
                    pass

            raise ZeroSSLRateLimitError(
                message=f"Rate limit exceeded: {error_message}",
                retry_after=retry_after
            )

        # Handle other errors
        raise ZeroSSLHTTPError(
            message=f"API request failed: {error_message}",
            status_code=response.status_code,
            response_data=error_data,
            request_url=url
        )

    def create_certificate(
        self,
        domains: List[str],
        csr: str,
        validity_days: int = 90
    ) -> Dict[str, Any]:
        """
        Create a new certificate.

        Args:
            domains: List of domains for the certificate
            csr: Certificate Signing Request content
            validity_days: Certificate validity period

        Returns:
            Certificate creation response

        Raises:
            ZeroSSLConfigurationError: If parameters are invalid
            ZeroSSLHTTPError: If API request fails
        """
        # Validate inputs
        validated_domains = validate_domains(domains)

        if not csr.strip():
            raise ZeroSSLConfigurationError("CSR content is required")

        if validity_days not in [90, 365]:
            raise ZeroSSLConfigurationError("Validity days must be 90 or 365")

        # Prepare request data
        data = {
            'certificate_domains': ','.join(validated_domains),
            'certificate_csr': csr.strip(),
            'certificate_validity_days': str(validity_days)
        }

        return self._make_request('POST', '/certificates', data=data)

    def get_certificate(self, certificate_id: str) -> Dict[str, Any]:
        """
        Get certificate information.

        Args:
            certificate_id: ZeroSSL certificate ID

        Returns:
            Certificate information

        Raises:
            ZeroSSLConfigurationError: If certificate ID is invalid
            ZeroSSLHTTPError: If API request fails
        """
        if not certificate_id:
            raise ZeroSSLConfigurationError("certificate_id is required")

        return self._make_request('GET', f'/certificates/{certificate_id}')

    def list_certificates(
        self,
        status: Optional[str] = None,
        page: int = 1,
        limit: int = 25
    ) -> Dict[str, Any]:
        """
        List certificates.

        Args:
            status: Filter by certificate status
            page: Page number (1-based)
            limit: Number of results per page

        Returns:
            Certificate list response

        Raises:
            ZeroSSLHTTPError: If API request fails
        """
        params = {
            'page': page,
            'limit': min(limit, 100)  # API maximum
        }

        if status:
            params['status'] = status

        return self._make_request('GET', '/certificates', params=params)

    def validate_certificate(
        self,
        certificate_id: str,
        validation_method: str
    ) -> Dict[str, Any]:
        """
        Trigger certificate validation.

        Args:
            certificate_id: ZeroSSL certificate ID
            validation_method: Validation method (HTTP_CSR_HASH or DNS_CSR_HASH)

        Returns:
            Validation response

        Raises:
            ZeroSSLConfigurationError: If parameters are invalid
            ZeroSSLHTTPError: If API request fails
        """
        if not certificate_id:
            raise ZeroSSLConfigurationError("certificate_id is required")

        if validation_method not in ['HTTP_CSR_HASH', 'DNS_CSR_HASH']:
            raise ZeroSSLConfigurationError(
                "validation_method must be 'HTTP_CSR_HASH' or 'DNS_CSR_HASH'"
            )

        data = {
            'validation_method': validation_method
        }

        return self._make_request('POST', f'/certificates/{certificate_id}/challenges', json=data)

    def download_certificate(self, certificate_id: str) -> bytes:
        """
        Download certificate files.

        Args:
            certificate_id: ZeroSSL certificate ID

        Returns:
            Certificate ZIP file content

        Raises:
            ZeroSSLConfigurationError: If certificate ID is invalid
            ZeroSSLHTTPError: If API request fails
        """
        if not certificate_id:
            raise ZeroSSLConfigurationError("certificate_id is required")

        url = self._build_url(f'/certificates/{certificate_id}/download')

        try:
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                return response.content
            else:
                self._handle_error_response(response, url)

        except requests.RequestException as e:
            raise ZeroSSLHTTPError(f"Download request failed: {e}")

    def cancel_certificate(self, certificate_id: str) -> Dict[str, Any]:
        """
        Cancel a certificate.

        Args:
            certificate_id: ZeroSSL certificate ID

        Returns:
            Cancellation response

        Raises:
            ZeroSSLConfigurationError: If certificate ID is invalid
            ZeroSSLHTTPError: If API request fails
        """
        if not certificate_id:
            raise ZeroSSLConfigurationError("certificate_id is required")

        return self._make_request('POST', f'/certificates/{certificate_id}/cancel')

    def get_verification_details(self, certificate_id: str) -> Dict[str, Any]:
        """
        Get verification details for a certificate.

        Args:
            certificate_id: ZeroSSL certificate ID

        Returns:
            Verification details

        Raises:
            ZeroSSLConfigurationError: If certificate ID is invalid
            ZeroSSLHTTPError: If API request fails
        """
        if not certificate_id:
            raise ZeroSSLConfigurationError("certificate_id is required")

        return self._make_request('GET', f'/certificates/{certificate_id}/verification')

    def close(self):
        """Close the HTTP session."""
        if hasattr(self, 'session'):
            self.session.close()

    def __del__(self):
        """Cleanup when object is destroyed."""
        self.close()
