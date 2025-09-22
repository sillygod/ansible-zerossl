# -*- coding: utf-8 -*-
"""
ZeroSSL utility functions.

This module provides validation utilities, domain checking functions,
and other helper utilities used throughout the ZeroSSL plugin.
"""

import re
import ipaddress
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse
import socket
import dns.resolver
from pathlib import Path

from .exceptions import ZeroSSLConfigurationError, ZeroSSLValidationError


def validate_domain(domain: str) -> bool:
    """
    Validate a domain name format.

    Args:
        domain: Domain name to validate

    Returns:
        True if domain is valid, False otherwise

    Raises:
        ZeroSSLConfigurationError: If domain format is invalid
    """
    if not domain:
        raise ZeroSSLConfigurationError("Domain cannot be empty")

    # Remove leading/trailing whitespace
    domain = domain.strip()

    # Check for wildcard domains
    if domain.startswith('*.'):
        # Validate the base domain without the wildcard
        base_domain = domain[2:]
        if not base_domain:
            raise ZeroSSLConfigurationError("Wildcard domain must have a base domain")
        domain = base_domain

    # RFC 1035 domain name validation
    if len(domain) > 253:
        raise ZeroSSLConfigurationError(f"Domain '{domain}' exceeds maximum length of 253 characters")

    # Split into labels
    labels = domain.split('.')
    if len(labels) < 2:
        raise ZeroSSLConfigurationError(f"Domain '{domain}' must have at least two labels")

    # Validate each label
    for i, label in enumerate(labels):
        if not label:
            raise ZeroSSLConfigurationError(f"Domain '{domain}' contains empty label")

        if len(label) > 63:
            raise ZeroSSLConfigurationError(f"Domain label '{label}' exceeds maximum length of 63 characters")

        # First and last character cannot be hyphen
        if label.startswith('-') or label.endswith('-'):
            raise ZeroSSLConfigurationError(f"Domain label '{label}' cannot start or end with hyphen")

        # Labels can only contain alphanumeric characters and hyphens
        if not re.match(r'^[a-zA-Z0-9-]+$', label):
            raise ZeroSSLConfigurationError(f"Domain label '{label}' contains invalid characters")

    return True


def validate_domains(domains: List[str]) -> List[str]:
    """
    Validate a list of domain names.

    Args:
        domains: List of domain names to validate

    Returns:
        List of validated domain names

    Raises:
        ZeroSSLConfigurationError: If any domain is invalid
    """
    if not domains:
        raise ZeroSSLConfigurationError("At least one domain is required")

    if len(domains) > 100:
        raise ZeroSSLConfigurationError("Maximum of 100 domains allowed per certificate")

    validated_domains = []
    seen_domains = set()

    for domain in domains:
        # Validate domain format
        validate_domain(domain)

        # Normalize domain (lowercase)
        normalized_domain = domain.lower().strip()

        # Check for duplicates
        if normalized_domain in seen_domains:
            raise ZeroSSLConfigurationError(f"Duplicate domain: {normalized_domain}")

        seen_domains.add(normalized_domain)
        validated_domains.append(normalized_domain)

    return validated_domains


def is_wildcard_domain(domain: str) -> bool:
    """
    Check if a domain is a wildcard domain.

    Args:
        domain: Domain to check

    Returns:
        True if domain is a wildcard domain
    """
    return domain.startswith('*.')


def extract_base_domain(domain: str) -> str:
    """
    Extract base domain from a domain (removes subdomain or wildcard).

    Args:
        domain: Domain to extract base from

    Returns:
        Base domain
    """
    if is_wildcard_domain(domain):
        return domain[2:]

    # Split into parts and take last two (domain.tld)
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def domains_overlap(domain1: str, domain2: str) -> bool:
    """
    Check if two domains overlap (one covers the other).

    Args:
        domain1: First domain
        domain2: Second domain

    Returns:
        True if domains overlap
    """
    # Exact match
    if domain1 == domain2:
        return True

    # Check if one is a wildcard that covers the other
    if is_wildcard_domain(domain1):
        base1 = extract_base_domain(domain1)
        return domain2.endswith('.' + base1) or domain2 == base1

    if is_wildcard_domain(domain2):
        base2 = extract_base_domain(domain2)
        return domain1.endswith('.' + base2) or domain1 == base2

    return False


def check_domain_dns_resolution(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Check if a domain resolves via DNS.

    Args:
        domain: Domain to check
        timeout: DNS resolution timeout in seconds

    Returns:
        Dictionary with resolution results
    """
    result = {
        'domain': domain,
        'resolves': False,
        'a_records': [],
        'aaaa_records': [],
        'error': None
    }

    try:
        # Set timeout for DNS resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        # Try A record resolution
        try:
            a_answers = resolver.resolve(domain, 'A')
            result['a_records'] = [str(rdata) for rdata in a_answers]
            result['resolves'] = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass

        # Try AAAA record resolution
        try:
            aaaa_answers = resolver.resolve(domain, 'AAAA')
            result['aaaa_records'] = [str(rdata) for rdata in aaaa_answers]
            result['resolves'] = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass

    except Exception as e:
        result['error'] = str(e)

    return result


def check_domain_http_accessibility(domain: str, port: int = 80, timeout: int = 10) -> Dict[str, Any]:
    """
    Check if a domain is accessible via HTTP.

    Args:
        domain: Domain to check
        port: Port to check (default 80)
        timeout: Connection timeout in seconds

    Returns:
        Dictionary with accessibility results
    """
    result = {
        'domain': domain,
        'port': port,
        'accessible': False,
        'error': None
    }

    try:
        # Try to connect to the domain
        sock = socket.create_connection((domain, port), timeout)
        sock.close()
        result['accessible'] = True
    except Exception as e:
        result['error'] = str(e)

    return result


def validate_file_path(file_path: str, must_exist: bool = False, must_be_writable: bool = False) -> str:
    """
    Validate a file path.

    Args:
        file_path: Path to validate
        must_exist: Whether the path must already exist
        must_be_writable: Whether the path must be writable

    Returns:
        Validated absolute path

    Raises:
        ZeroSSLConfigurationError: If path validation fails
    """
    if not file_path:
        raise ZeroSSLConfigurationError("File path cannot be empty")

    path = Path(file_path).expanduser().resolve()

    if must_exist and not path.exists():
        raise ZeroSSLConfigurationError(f"Path does not exist: {path}")

    if must_be_writable:
        # Check if parent directory is writable
        parent = path.parent
        if not parent.exists():
            try:
                parent.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                raise ZeroSSLConfigurationError(f"Cannot create directory: {parent}")

        if not parent.is_dir():
            raise ZeroSSLConfigurationError(f"Parent is not a directory: {parent}")

        # Test write access
        try:
            test_file = parent / '.ansible_zerossl_write_test'
            test_file.touch()
            test_file.unlink()
        except PermissionError:
            raise ZeroSSLConfigurationError(f"Directory is not writable: {parent}")

    return str(path)


def validate_api_key(api_key: str) -> str:
    """
    Validate ZeroSSL API key format.

    Args:
        api_key: API key to validate

    Returns:
        Validated API key

    Raises:
        ZeroSSLConfigurationError: If API key is invalid
    """
    if not api_key:
        raise ZeroSSLConfigurationError("API key is required")

    api_key = api_key.strip()

    if len(api_key) < 20:
        raise ZeroSSLConfigurationError("API key appears to be too short")

    if len(api_key) > 200:
        raise ZeroSSLConfigurationError("API key appears to be too long")

    # Check for basic format (alphanumeric and some special chars)
    if not re.match(r'^[a-zA-Z0-9_-]+$', api_key):
        raise ZeroSSLConfigurationError("API key contains invalid characters")

    return api_key


def parse_validation_url(url: str) -> Dict[str, str]:
    """
    Parse a validation URL to extract components.

    Args:
        url: Validation URL to parse

    Returns:
        Dictionary with URL components

    Raises:
        ZeroSSLValidationError: If URL is malformed
    """
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ZeroSSLValidationError(f"Invalid validation URL: {e}")

    if not parsed.scheme:
        raise ZeroSSLValidationError("Validation URL must include scheme (http/https)")

    if not parsed.netloc:
        raise ZeroSSLValidationError("Validation URL must include domain")

    if not parsed.path:
        raise ZeroSSLValidationError("Validation URL must include path")

    # Extract filename from path
    path_parts = parsed.path.strip('/').split('/')
    filename = path_parts[-1] if path_parts else ''

    if not filename:
        raise ZeroSSLValidationError("Validation URL must include filename")

    return {
        'scheme': parsed.scheme,
        'domain': parsed.netloc,
        'path': parsed.path,
        'filename': filename,
        'full_url': url
    }


def generate_csr(domains: List[str], private_key_path: Optional[str] = None) -> Tuple[str, str]:
    """
    Generate a Certificate Signing Request (CSR) for the given domains.

    Args:
        domains: List of domains for the certificate
        private_key_path: Optional path to existing private key

    Returns:
        Tuple of (CSR content, private key content)

    Raises:
        ZeroSSLConfigurationError: If CSR generation fails
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        raise ZeroSSLConfigurationError("cryptography library is required for CSR generation")

    # Generate or load private key
    if private_key_path and Path(private_key_path).exists():
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        # Generate new private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    # Build subject name
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ])

    # Build CSR
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)

    # Add Subject Alternative Names if multiple domains
    if len(domains) > 1:
        san_list = [x509.DNSName(domain) for domain in domains]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

    # Add key usage
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # Add extended key usage
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=True,
    )

    # Sign the CSR
    csr = builder.sign(private_key, hashes.SHA256())

    # Serialize to PEM format
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    return csr_pem, private_key_pem


def normalize_certificate_content(content: str) -> str:
    """
    Normalize certificate content to standard PEM format.

    Args:
        content: Certificate content to normalize

    Returns:
        Normalized certificate content
    """
    if not content:
        return content

    # Remove extra whitespace and ensure proper line endings
    lines = [line.strip() for line in content.split('\n') if line.strip()]
    return '\n'.join(lines) + '\n'


def extract_certificate_info(cert_content: str) -> Dict[str, Any]:
    """
    Extract information from a certificate.

    Args:
        cert_content: PEM-formatted certificate content

    Returns:
        Dictionary with certificate information

    Raises:
        ZeroSSLValidationError: If certificate parsing fails
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        raise ZeroSSLConfigurationError("cryptography library is required for certificate parsing")

    try:
        cert = x509.load_pem_x509_certificate(cert_content.encode('utf-8'))
    except Exception as e:
        raise ZeroSSLValidationError(f"Failed to parse certificate: {e}")

    # Extract basic information
    info = {
        'subject': str(cert.subject),
        'issuer': str(cert.issuer),
        'serial_number': str(cert.serial_number),
        'not_valid_before': cert.not_valid_before.isoformat(),
        'not_valid_after': cert.not_valid_after.isoformat(),
        'signature_algorithm': cert.signature_algorithm_oid._name,
        'domains': []
    }

    # Extract domains from subject and SAN
    subject_cn = None
    for attribute in cert.subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            subject_cn = attribute.value
            break

    if subject_cn:
        info['domains'].append(subject_cn)

    # Extract SAN domains
    try:
        san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_extension.value:
            if isinstance(name, x509.DNSName):
                if name.value not in info['domains']:
                    info['domains'].append(name.value)
    except x509.ExtensionNotFound:
        pass

    return info


def create_file_with_permissions(file_path: str, content: str, mode: int = 0o600) -> None:
    """
    Create a file with specific permissions.

    Args:
        file_path: Path to create file at
        content: Content to write to file
        mode: File permissions mode

    Raises:
        ZeroSSLFileSystemError: If file creation fails
    """
    from .exceptions import ZeroSSLFileSystemError

    try:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)
    except PermissionError as e:
        raise ZeroSSLFileSystemError(
            f"Permission denied creating file: {file_path}",
            file_path=file_path,
            operation="create",
            permissions_needed=oct(mode)
        )
    except OSError as e:
        raise ZeroSSLFileSystemError(
            f"Failed to create file: {e}",
            file_path=file_path,
            operation="create"
        )
