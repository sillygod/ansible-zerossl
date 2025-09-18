# -*- coding: utf-8 -*-
"""
ZeroSSL Concurrent Operation Support.

This module provides thread-safe mechanisms for concurrent certificate operations,
including proper locking and coordination to prevent race conditions.
"""

import time
import threading
from typing import Dict, Any, Optional, Set, Callable
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path

from .exceptions import ZeroSSLConcurrencyError, ZeroSSLTimeoutError


@dataclass
class OperationLock:
    """Represents a lock for a specific operation."""
    resource_id: str
    operation_type: str
    thread_id: int
    acquired_at: float
    expires_at: Optional[float] = None


class ConcurrencyManager:
    """
    Thread-safe manager for concurrent certificate operations.

    Provides locking mechanisms to prevent conflicts when multiple
    operations target the same certificate or domain resources.
    """

    def __init__(
        self,
        lock_timeout: int = 300,  # 5 minutes
        cleanup_interval: int = 60  # 1 minute
    ):
        """
        Initialize concurrency manager.

        Args:
            lock_timeout: Maximum time to hold locks in seconds
            cleanup_interval: Interval for cleaning expired locks
        """
        self.lock_timeout = lock_timeout
        self.cleanup_interval = cleanup_interval

        # Thread-safe storage for active locks
        self._locks: Dict[str, OperationLock] = {}
        self._lock_mutex = threading.RLock()

        # Track operations by certificate ID and domain
        self._cert_operations: Set[str] = set()
        self._domain_operations: Set[str] = set()

        # Background cleanup thread
        self._cleanup_thread = None
        self._cleanup_stop_event = threading.Event()
        self._start_cleanup_thread()

    def _start_cleanup_thread(self):
        """Start background thread for lock cleanup."""
        if self._cleanup_thread is None or not self._cleanup_thread.is_alive():
            self._cleanup_stop_event.clear()
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_expired_locks,
                daemon=True
            )
            self._cleanup_thread.start()

    def _cleanup_expired_locks(self):
        """Background cleanup of expired locks."""
        while not self._cleanup_stop_event.wait(self.cleanup_interval):
            try:
                self.cleanup_expired_locks()
            except Exception:
                # Silently continue - cleanup errors shouldn't break operations
                pass

    def _generate_lock_key(self, resource_id: str, operation_type: str) -> str:
        """Generate unique lock key for resource and operation."""
        return f"{operation_type}:{resource_id}"

    @contextmanager
    def acquire_certificate_lock(
        self,
        certificate_id: str,
        operation_type: str,
        timeout: Optional[int] = None
    ):
        """
        Acquire exclusive lock for certificate operation.

        Args:
            certificate_id: ZeroSSL certificate ID
            operation_type: Type of operation (create, validate, download, etc.)
            timeout: Maximum time to wait for lock

        Yields:
            Lock context

        Raises:
            ZeroSSLConcurrencyError: If lock cannot be acquired
        """
        lock_key = self._generate_lock_key(certificate_id, operation_type)
        effective_timeout = timeout or self.lock_timeout

        try:
            self._acquire_lock(lock_key, certificate_id, operation_type, effective_timeout)

            # Track certificate operation
            with self._lock_mutex:
                self._cert_operations.add(certificate_id)

            yield

        finally:
            self._release_lock(lock_key)
            with self._lock_mutex:
                self._cert_operations.discard(certificate_id)

    @contextmanager
    def acquire_domain_lock(
        self,
        domain: str,
        operation_type: str,
        timeout: Optional[int] = None
    ):
        """
        Acquire exclusive lock for domain operation.

        Args:
            domain: Domain name
            operation_type: Type of operation (validation, etc.)
            timeout: Maximum time to wait for lock

        Yields:
            Lock context

        Raises:
            ZeroSSLConcurrencyError: If lock cannot be acquired
        """
        # Normalize domain name
        normalized_domain = domain.lower().strip()
        lock_key = self._generate_lock_key(normalized_domain, operation_type)
        effective_timeout = timeout or self.lock_timeout

        try:
            self._acquire_lock(lock_key, normalized_domain, operation_type, effective_timeout)

            # Track domain operation
            with self._lock_mutex:
                self._domain_operations.add(normalized_domain)

            yield

        finally:
            self._release_lock(lock_key)
            with self._lock_mutex:
                self._domain_operations.discard(normalized_domain)

    @contextmanager
    def acquire_multi_domain_lock(
        self,
        domains: list,
        operation_type: str,
        timeout: Optional[int] = None
    ):
        """
        Acquire locks for multiple domains atomically.

        Args:
            domains: List of domain names
            operation_type: Type of operation
            timeout: Maximum time to wait for all locks

        Yields:
            Lock context

        Raises:
            ZeroSSLConcurrencyError: If any lock cannot be acquired
        """
        # Sort domains to prevent deadlocks
        sorted_domains = sorted([d.lower().strip() for d in domains])
        lock_keys = [self._generate_lock_key(domain, operation_type) for domain in sorted_domains]
        effective_timeout = timeout or self.lock_timeout

        acquired_locks = []

        try:
            # Acquire locks in order
            for i, (domain, lock_key) in enumerate(zip(sorted_domains, lock_keys)):
                remaining_timeout = max(0, effective_timeout - (time.time() - time.time()))
                self._acquire_lock(lock_key, domain, operation_type, remaining_timeout)
                acquired_locks.append(lock_key)

                # Track domain operation
                with self._lock_mutex:
                    self._domain_operations.add(domain)

            yield

        finally:
            # Release locks in reverse order
            for lock_key in reversed(acquired_locks):
                self._release_lock(lock_key)

            # Clean up domain tracking
            with self._lock_mutex:
                for domain in sorted_domains:
                    self._domain_operations.discard(domain)

    def _acquire_lock(
        self,
        lock_key: str,
        resource_id: str,
        operation_type: str,
        timeout: int
    ):
        """
        Acquire a specific lock with timeout.

        Args:
            lock_key: Unique lock identifier
            resource_id: Resource being locked
            operation_type: Type of operation
            timeout: Maximum wait time

        Raises:
            ZeroSSLConcurrencyError: If lock cannot be acquired
        """
        start_time = time.time()
        thread_id = threading.get_ident()

        while True:
            with self._lock_mutex:
                # Check if lock is available
                if lock_key not in self._locks:
                    # Acquire the lock
                    expires_at = time.time() + self.lock_timeout
                    self._locks[lock_key] = OperationLock(
                        resource_id=resource_id,
                        operation_type=operation_type,
                        thread_id=thread_id,
                        acquired_at=time.time(),
                        expires_at=expires_at
                    )
                    return

                # Check if current thread already owns the lock (reentrant)
                existing_lock = self._locks[lock_key]
                if existing_lock.thread_id == thread_id:
                    # Update expiration time
                    existing_lock.expires_at = time.time() + self.lock_timeout
                    return

                # Check if existing lock has expired
                if (existing_lock.expires_at and
                    time.time() > existing_lock.expires_at):
                    # Remove expired lock and try again
                    del self._locks[lock_key]
                    continue

            # Check timeout
            if time.time() - start_time > timeout:
                raise ZeroSSLConcurrencyError(
                    f"Failed to acquire lock for {operation_type} on {resource_id}",
                    resource_id=resource_id,
                    operation_type=operation_type,
                    timeout_duration=timeout
                )

            # Wait before retrying
            time.sleep(0.1)

    def _release_lock(self, lock_key: str):
        """
        Release a specific lock.

        Args:
            lock_key: Lock identifier to release
        """
        thread_id = threading.get_ident()

        with self._lock_mutex:
            if lock_key in self._locks:
                existing_lock = self._locks[lock_key]

                # Only release if owned by current thread
                if existing_lock.thread_id == thread_id:
                    del self._locks[lock_key]

    def is_certificate_locked(self, certificate_id: str) -> bool:
        """
        Check if certificate has any active locks.

        Args:
            certificate_id: Certificate ID to check

        Returns:
            True if certificate is locked
        """
        with self._lock_mutex:
            return certificate_id in self._cert_operations

    def is_domain_locked(self, domain: str) -> bool:
        """
        Check if domain has any active locks.

        Args:
            domain: Domain to check

        Returns:
            True if domain is locked
        """
        normalized_domain = domain.lower().strip()
        with self._lock_mutex:
            return normalized_domain in self._domain_operations

    def get_active_locks(self) -> Dict[str, OperationLock]:
        """
        Get all currently active locks.

        Returns:
            Dictionary of active locks
        """
        with self._lock_mutex:
            return self._locks.copy()

    def cleanup_expired_locks(self) -> int:
        """
        Clean up expired locks.

        Returns:
            Number of locks cleaned up
        """
        current_time = time.time()
        cleaned_count = 0

        with self._lock_mutex:
            expired_keys = []

            for lock_key, lock in self._locks.items():
                if lock.expires_at and current_time > lock.expires_at:
                    expired_keys.append(lock_key)

            for lock_key in expired_keys:
                del self._locks[lock_key]
                cleaned_count += 1

        return cleaned_count

    def force_release_lock(self, resource_id: str, operation_type: str) -> bool:
        """
        Force release a specific lock.

        Args:
            resource_id: Resource identifier
            operation_type: Operation type

        Returns:
            True if lock was found and released
        """
        lock_key = self._generate_lock_key(resource_id, operation_type)

        with self._lock_mutex:
            if lock_key in self._locks:
                del self._locks[lock_key]
                return True

        return False

    def get_lock_stats(self) -> Dict[str, Any]:
        """
        Get concurrency statistics.

        Returns:
            Dictionary with lock statistics
        """
        with self._lock_mutex:
            active_locks = len(self._locks)
            cert_operations = len(self._cert_operations)
            domain_operations = len(self._domain_operations)

            # Count locks by operation type
            operation_counts = {}
            for lock in self._locks.values():
                operation_counts[lock.operation_type] = (
                    operation_counts.get(lock.operation_type, 0) + 1
                )

        return {
            'active_locks': active_locks,
            'certificate_operations': cert_operations,
            'domain_operations': domain_operations,
            'operation_counts': operation_counts,
            'lock_timeout': self.lock_timeout,
            'cleanup_interval': self.cleanup_interval
        }

    def shutdown(self):
        """Shutdown the concurrency manager and cleanup resources."""
        # Stop cleanup thread
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_stop_event.set()
            self._cleanup_thread.join(timeout=5)

        # Clear all locks
        with self._lock_mutex:
            self._locks.clear()
            self._cert_operations.clear()
            self._domain_operations.clear()

    def __del__(self):
        """Cleanup when object is destroyed."""
        self.shutdown()


class FileOperationManager:
    """
    Manager for thread-safe file operations.

    Provides coordination for file system operations to prevent
    conflicts when multiple threads access the same files.
    """

    def __init__(self):
        """Initialize file operation manager."""
        self._file_locks: Dict[str, threading.RLock] = {}
        self._locks_mutex = threading.RLock()

    def _get_file_lock(self, file_path: str) -> threading.RLock:
        """Get or create lock for specific file path."""
        normalized_path = str(Path(file_path).resolve())

        with self._locks_mutex:
            if normalized_path not in self._file_locks:
                self._file_locks[normalized_path] = threading.RLock()
            return self._file_locks[normalized_path]

    @contextmanager
    def acquire_file_lock(self, file_path: str):
        """
        Acquire exclusive lock for file operations.

        Args:
            file_path: Path to file being accessed

        Yields:
            Lock context
        """
        file_lock = self._get_file_lock(file_path)
        with file_lock:
            yield

    def safe_write_file(
        self,
        file_path: str,
        content: str,
        mode: int = 0o600,
        backup: bool = True
    ):
        """
        Thread-safe file writing with optional backup.

        Args:
            file_path: Target file path
            content: Content to write
            mode: File permissions
            backup: Whether to create backup

        Raises:
            ZeroSSLConcurrencyError: If write operation fails
        """
        path_obj = Path(file_path)

        with self.acquire_file_lock(file_path):
            try:
                # Create backup if requested and file exists
                if backup and path_obj.exists():
                    backup_path = f"{file_path}.backup"
                    path_obj.rename(backup_path)

                # Ensure parent directory exists
                path_obj.parent.mkdir(parents=True, exist_ok=True)

                # Write content atomically
                temp_path = f"{file_path}.tmp"
                with open(temp_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                # Set permissions and move to final location
                Path(temp_path).chmod(mode)
                Path(temp_path).rename(file_path)

            except Exception as e:
                raise ZeroSSLConcurrencyError(
                    f"Failed to write file {file_path}: {e}",
                    resource_id=file_path,
                    operation_type="file_write"
                )

    def safe_read_file(self, file_path: str) -> str:
        """
        Thread-safe file reading.

        Args:
            file_path: File path to read

        Returns:
            File content

        Raises:
            ZeroSSLConcurrencyError: If read operation fails
        """
        with self.acquire_file_lock(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                raise ZeroSSLConcurrencyError(
                    f"Failed to read file {file_path}: {e}",
                    resource_id=file_path,
                    operation_type="file_read"
                )


# Global instances for convenience
_concurrency_manager = None
_file_manager = None


def get_concurrency_manager() -> ConcurrencyManager:
    """Get or create global concurrency manager instance."""
    global _concurrency_manager
    if _concurrency_manager is None:
        _concurrency_manager = ConcurrencyManager()
    return _concurrency_manager


def get_file_manager() -> FileOperationManager:
    """Get or create global file operation manager instance."""
    global _file_manager
    if _file_manager is None:
        _file_manager = FileOperationManager()
    return _file_manager


# Convenience functions
def acquire_certificate_lock(certificate_id: str, operation_type: str, timeout: Optional[int] = None):
    """Acquire lock for certificate operation."""
    return get_concurrency_manager().acquire_certificate_lock(certificate_id, operation_type, timeout)


def acquire_domain_lock(domain: str, operation_type: str, timeout: Optional[int] = None):
    """Acquire lock for domain operation."""
    return get_concurrency_manager().acquire_domain_lock(domain, operation_type, timeout)


def acquire_multi_domain_lock(domains: list, operation_type: str, timeout: Optional[int] = None):
    """Acquire locks for multiple domains."""
    return get_concurrency_manager().acquire_multi_domain_lock(domains, operation_type, timeout)


def safe_write_file(file_path: str, content: str, mode: int = 0o600, backup: bool = True):
    """Thread-safe file writing."""
    return get_file_manager().safe_write_file(file_path, content, mode, backup)


def safe_read_file(file_path: str) -> str:
    """Thread-safe file reading."""
    return get_file_manager().safe_read_file(file_path)
