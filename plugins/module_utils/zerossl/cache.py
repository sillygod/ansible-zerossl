# -*- coding: utf-8 -*-
"""
ZeroSSL Certificate Caching Mechanism.

This module provides intelligent caching for certificate data to reduce
API calls and improve performance during certificate operations.
"""

import json
import time
import hashlib
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
from datetime import datetime, timedelta

from .exceptions import ZeroSSLFileSystemError, ZeroSSLConfigurationError


class CertificateCache:
    """
    Certificate information caching system.

    Provides intelligent caching of certificate data, API responses,
    and operation results to reduce API calls and improve performance.
    """

    def __init__(
        self,
        cache_dir: str = "/tmp/ansible-zerossl-cache",
        default_ttl: int = 300,  # 5 minutes
        max_cache_size: int = 100,  # Maximum number of cached items
        enable_persistence: bool = True
    ):
        """
        Initialize certificate cache.

        Args:
            cache_dir: Directory to store persistent cache files
            default_ttl: Default time-to-live for cache entries in seconds
            max_cache_size: Maximum number of items to keep in cache
            enable_persistence: Whether to persist cache to disk
        """
        self.cache_dir = Path(cache_dir)
        self.default_ttl = default_ttl
        self.max_cache_size = max_cache_size
        self.enable_persistence = enable_persistence

        # In-memory cache for fast access
        self._memory_cache: Dict[str, Dict[str, Any]] = {}

        # Cache statistics
        self._stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'disk_reads': 0,
            'disk_writes': 0
        }

        # Initialize cache directory
        if self.enable_persistence:
            self._init_cache_directory()

    def _init_cache_directory(self):
        """Initialize cache directory with proper permissions."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except PermissionError:
            raise ZeroSSLFileSystemError(
                f"Cannot create cache directory: {self.cache_dir}",
                file_path=str(self.cache_dir),
                operation="mkdir",
                permissions_needed="0700"
            )

    def _generate_cache_key(self, operation: str, **kwargs) -> str:
        """Generate cache key for operation with parameters."""
        # Create a deterministic key from operation and parameters
        key_data = json.dumps({
            'operation': operation,
            'params': sorted(kwargs.items())
        }, sort_keys=True)

        return hashlib.sha256(key_data.encode()).hexdigest()[:16]

    def _get_cache_file_path(self, cache_key: str) -> Path:
        """Get file path for persistent cache entry."""
        return self.cache_dir / f"{cache_key}.json"

    def get(
        self,
        operation: str,
        ttl: Optional[int] = None,
        **kwargs
    ) -> Optional[Any]:
        """
        Get cached data for operation.

        Args:
            operation: Operation identifier (e.g., 'certificate_status', 'api_list')
            ttl: Custom TTL for this operation
            **kwargs: Operation parameters used for cache key generation

        Returns:
            Cached data if found and valid, None otherwise
        """
        cache_key = self._generate_cache_key(operation, **kwargs)
        current_time = time.time()

        # Check in-memory cache first
        if cache_key in self._memory_cache:
            entry = self._memory_cache[cache_key]
            if current_time < entry['expires_at']:
                self._stats['hits'] += 1
                entry['last_accessed'] = current_time
                return entry['data']
            else:
                # Expired, remove from memory
                del self._memory_cache[cache_key]

        # Check persistent cache if enabled
        if self.enable_persistence:
            cache_file = self._get_cache_file_path(cache_key)
            if cache_file.exists():
                try:
                    with open(cache_file, 'r') as f:
                        entry = json.load(f)

                    if current_time < entry['expires_at']:
                        # Valid persistent cache entry, load into memory
                        self._memory_cache[cache_key] = entry
                        entry['last_accessed'] = current_time
                        self._stats['hits'] += 1
                        self._stats['disk_reads'] += 1
                        return entry['data']
                    else:
                        # Expired, remove file
                        cache_file.unlink(missing_ok=True)

                except (json.JSONDecodeError, KeyError, OSError):
                    # Corrupted cache file, remove it
                    cache_file.unlink(missing_ok=True)

        self._stats['misses'] += 1
        return None

    def set(
        self,
        operation: str,
        data: Any,
        ttl: Optional[int] = None,
        **kwargs
    ) -> None:
        """
        Store data in cache.

        Args:
            operation: Operation identifier
            data: Data to cache
            ttl: Custom TTL for this entry
            **kwargs: Operation parameters used for cache key generation
        """
        cache_key = self._generate_cache_key(operation, **kwargs)
        current_time = time.time()
        effective_ttl = ttl or self.default_ttl

        # Create cache entry
        entry = {
            'data': data,
            'created_at': current_time,
            'expires_at': current_time + effective_ttl,
            'last_accessed': current_time,
            'operation': operation,
            'params': kwargs
        }

        # Store in memory cache
        self._memory_cache[cache_key] = entry

        # Enforce memory cache size limit
        self._enforce_cache_size_limit()

        # Store in persistent cache if enabled
        if self.enable_persistence:
            try:
                cache_file = self._get_cache_file_path(cache_key)
                with open(cache_file, 'w') as f:
                    json.dump(entry, f)
                cache_file.chmod(0o600)
                self._stats['disk_writes'] += 1
            except OSError:
                # Disk write failed, continue without persistence
                pass

    def _enforce_cache_size_limit(self):
        """Enforce maximum cache size by evicting least recently used entries."""
        if len(self._memory_cache) <= self.max_cache_size:
            return

        # Sort by last_accessed and remove oldest entries
        sorted_entries = sorted(
            self._memory_cache.items(),
            key=lambda x: x[1]['last_accessed']
        )

        entries_to_remove = len(self._memory_cache) - self.max_cache_size
        for cache_key, _ in sorted_entries[:entries_to_remove]:
            del self._memory_cache[cache_key]
            self._stats['evictions'] += 1

            # Also remove from persistent storage
            if self.enable_persistence:
                cache_file = self._get_cache_file_path(cache_key)
                cache_file.unlink(missing_ok=True)

    def invalidate(self, operation: str, **kwargs) -> bool:
        """
        Invalidate specific cache entry.

        Args:
            operation: Operation identifier
            **kwargs: Operation parameters

        Returns:
            True if entry was found and removed, False otherwise
        """
        cache_key = self._generate_cache_key(operation, **kwargs)

        # Remove from memory cache
        memory_removed = cache_key in self._memory_cache
        if memory_removed:
            del self._memory_cache[cache_key]

        # Remove from persistent cache
        disk_removed = False
        if self.enable_persistence:
            cache_file = self._get_cache_file_path(cache_key)
            if cache_file.exists():
                cache_file.unlink()
                disk_removed = True

        return memory_removed or disk_removed

    def invalidate_pattern(self, operation_pattern: str) -> int:
        """
        Invalidate all cache entries matching operation pattern.

        Args:
            operation_pattern: Pattern to match operation names

        Returns:
            Number of entries invalidated
        """
        invalidated_count = 0

        # Memory cache
        keys_to_remove = []
        for cache_key, entry in self._memory_cache.items():
            if operation_pattern in entry.get('operation', ''):
                keys_to_remove.append(cache_key)

        for cache_key in keys_to_remove:
            del self._memory_cache[cache_key]
            invalidated_count += 1

        # Persistent cache
        if self.enable_persistence:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r') as f:
                        entry = json.load(f)

                    if operation_pattern in entry.get('operation', ''):
                        cache_file.unlink()
                        invalidated_count += 1

                except (json.JSONDecodeError, OSError):
                    # Corrupted or inaccessible file, remove it
                    cache_file.unlink(missing_ok=True)

        return invalidated_count

    def clear(self) -> int:
        """
        Clear all cache entries.

        Returns:
            Number of entries cleared
        """
        # Count entries before clearing
        total_entries = len(self._memory_cache)

        # Clear memory cache
        self._memory_cache.clear()

        # Clear persistent cache
        if self.enable_persistence:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    cache_file.unlink()
                    total_entries += 1
                except OSError:
                    pass

        return total_entries

    def cleanup_expired(self) -> int:
        """
        Remove expired entries from cache.

        Returns:
            Number of expired entries removed
        """
        current_time = time.time()
        removed_count = 0

        # Clean memory cache
        expired_keys = []
        for cache_key, entry in self._memory_cache.items():
            if current_time >= entry['expires_at']:
                expired_keys.append(cache_key)

        for cache_key in expired_keys:
            del self._memory_cache[cache_key]
            removed_count += 1

        # Clean persistent cache
        if self.enable_persistence:
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    with open(cache_file, 'r') as f:
                        entry = json.load(f)

                    if current_time >= entry['expires_at']:
                        cache_file.unlink()
                        removed_count += 1

                except (json.JSONDecodeError, OSError):
                    # Corrupted file, remove it
                    cache_file.unlink(missing_ok=True)
                    removed_count += 1

        return removed_count

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache performance statistics
        """
        total_requests = self._stats['hits'] + self._stats['misses']
        hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0

        return {
            'hits': self._stats['hits'],
            'misses': self._stats['misses'],
            'hit_rate_percent': round(hit_rate, 2),
            'evictions': self._stats['evictions'],
            'disk_reads': self._stats['disk_reads'],
            'disk_writes': self._stats['disk_writes'],
            'memory_entries': len(self._memory_cache),
            'cache_size_mb': self._estimate_cache_size(),
            'cache_directory': str(self.cache_dir)
        }

    def _estimate_cache_size(self) -> float:
        """Estimate cache size in MB."""
        try:
            # Estimate memory cache size
            memory_size = 0
            for entry in self._memory_cache.values():
                memory_size += len(json.dumps(entry).encode())

            # Estimate disk cache size
            disk_size = 0
            if self.enable_persistence and self.cache_dir.exists():
                for cache_file in self.cache_dir.glob("*.json"):
                    try:
                        disk_size += cache_file.stat().st_size
                    except OSError:
                        pass

            total_size_mb = (memory_size + disk_size) / (1024 * 1024)
            return round(total_size_mb, 2)

        except Exception:
            return 0.0


class CertificateCacheManager:
    """
    High-level cache manager for certificate operations.

    Provides operation-specific caching methods with appropriate TTL values
    and cache invalidation strategies.
    """

    def __init__(self, cache: Optional[CertificateCache] = None):
        """
        Initialize cache manager.

        Args:
            cache: CertificateCache instance, creates default if None
        """
        self.cache = cache or CertificateCache()

        # Operation-specific TTL values
        self._operation_ttls = {
            'certificate_status': 120,  # 2 minutes
            'certificate_list': 300,    # 5 minutes
            'api_validation': 60,       # 1 minute
            'domain_validation': 30,    # 30 seconds
            'certificate_download': 3600  # 1 hour (certificates don't change)
        }

    def get_certificate_status(self, certificate_id: str) -> Optional[Dict[str, Any]]:
        """Get cached certificate status."""
        return self.cache.get(
            'certificate_status',
            certificate_id=certificate_id,
            ttl=self._operation_ttls['certificate_status']
        )

    def set_certificate_status(self, certificate_id: str, status_data: Dict[str, Any]) -> None:
        """Cache certificate status."""
        self.cache.set(
            'certificate_status',
            status_data,
            certificate_id=certificate_id,
            ttl=self._operation_ttls['certificate_status']
        )

    def get_certificate_list(self, api_key_hash: str, filters: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Get cached certificate list."""
        filters = filters or {}
        return self.cache.get(
            'certificate_list',
            api_key_hash=api_key_hash,
            filters=filters,
            ttl=self._operation_ttls['certificate_list']
        )

    def set_certificate_list(self, api_key_hash: str, list_data: Dict[str, Any], filters: Dict[str, Any] = None) -> None:
        """Cache certificate list."""
        filters = filters or {}
        self.cache.set(
            'certificate_list',
            list_data,
            api_key_hash=api_key_hash,
            filters=filters,
            ttl=self._operation_ttls['certificate_list']
        )

    def get_validation_result(self, certificate_id: str, validation_method: str) -> Optional[Dict[str, Any]]:
        """Get cached validation result."""
        return self.cache.get(
            'api_validation',
            certificate_id=certificate_id,
            validation_method=validation_method,
            ttl=self._operation_ttls['api_validation']
        )

    def set_validation_result(self, certificate_id: str, validation_method: str, result: Dict[str, Any]) -> None:
        """Cache validation result."""
        self.cache.set(
            'api_validation',
            result,
            certificate_id=certificate_id,
            validation_method=validation_method,
            ttl=self._operation_ttls['api_validation']
        )

    def get_domain_validation_check(self, domain: str, validation_token: str) -> Optional[Dict[str, Any]]:
        """Get cached domain validation check result."""
        return self.cache.get(
            'domain_validation',
            domain=domain,
            validation_token=validation_token,
            ttl=self._operation_ttls['domain_validation']
        )

    def set_domain_validation_check(self, domain: str, validation_token: str, result: Dict[str, Any]) -> None:
        """Cache domain validation check result."""
        self.cache.set(
            'domain_validation',
            result,
            domain=domain,
            validation_token=validation_token,
            ttl=self._operation_ttls['domain_validation']
        )

    def invalidate_certificate(self, certificate_id: str) -> None:
        """Invalidate all cache entries for a specific certificate."""
        self.cache.invalidate('certificate_status', certificate_id=certificate_id)
        self.cache.invalidate_pattern(f'certificate_{certificate_id}')

    def invalidate_api_key_cache(self, api_key_hash: str) -> None:
        """Invalidate all cache entries for a specific API key."""
        self.cache.invalidate_pattern(f'api_key_{api_key_hash}')

    def cleanup_expired_entries(self) -> int:
        """Clean up expired cache entries."""
        return self.cache.cleanup_expired()

    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        return self.cache.get_stats()


def create_api_key_hash(api_key: str) -> str:
    """
    Create a hash of the API key for cache identification.

    Args:
        api_key: ZeroSSL API key

    Returns:
        SHA256 hash of the API key (first 16 characters)
    """
    return hashlib.sha256(api_key.encode()).hexdigest()[:16]
