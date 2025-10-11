# -*- coding: utf-8 -*-
"""
Performance Tests for ZeroSSL Concurrent Operations.

Tests for concurrent certificate operations, rate limiting, and performance
under various load conditions.
"""

import pytest
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import patch, Mock

try:
    from ansible.module_utils.zerossl.concurrency import (
        ConcurrencyManager,
        FileOperationManager,
        acquire_certificate_lock,
        acquire_domain_lock,
        acquire_multi_domain_lock,
    )
    from ansible.module_utils.zerossl.cache import CertificateCacheManager
    from ansible.module_utils.zerossl.api_client import ZeroSSLAPIClient
    from ansible.module_utils.zerossl.certificate_manager import CertificateManager
except ImportError:
    import sys
    import os

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from plugins.module_utils.zerossl.concurrency import (
        ConcurrencyManager,
        FileOperationManager,
        acquire_certificate_lock,
        acquire_domain_lock,
        acquire_multi_domain_lock,
    )
    from plugins.module_utils.zerossl.cache import CertificateCacheManager
    from plugins.module_utils.zerossl.api_client import ZeroSSLAPIClient
    from plugins.module_utils.zerossl.certificate_manager import CertificateManager

from tests.fixtures import (
    MockZeroSSLAPIClient,
    MockCertificateManager,
    PERFORMANCE_TEST_DATA,
    create_test_file_structure,
)


class TestConcurrentOperations:
    """Test concurrent certificate operations."""

    def setup_method(self):
        """Setup for each test method."""
        self.concurrency_manager = ConcurrencyManager()
        self.file_manager = FileOperationManager()

    def teardown_method(self):
        """Cleanup after each test method."""
        if hasattr(self, "concurrency_manager"):
            self.concurrency_manager.shutdown()

    def test_concurrent_certificate_locks(self):
        """Test concurrent acquisition of certificate locks."""
        certificate_id = "test-cert-123"
        operation_type = "test_operation"
        num_threads = 10
        results = []

        def try_acquire_lock(thread_id):
            try:
                with acquire_certificate_lock(certificate_id, operation_type, timeout=5):
                    time.sleep(0.05)  # Simulate work - reduced time to avoid timeouts
                    results.append(f"thread_{thread_id}_success")
                    return True
            except Exception as e:
                results.append(f"thread_{thread_id}_failed_{type(e).__name__}")
                return False

        # Run concurrent lock attempts
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(try_acquire_lock, i) for i in range(num_threads)]

            completed = sum(1 for future in as_completed(futures) if future.result())

        # Only one thread should succeed at a time, but all should eventually succeed
        assert len(results) == num_threads
        successful_results = [r for r in results if "success" in r]
        assert len(successful_results) == num_threads

    def test_concurrent_domain_locks(self):
        """Test concurrent domain locking with overlapping domains."""
        domains_sets = [
            ["example1.com", "example2.com"],
            ["example2.com", "example3.com"],
            ["example1.com", "example3.com"],
            ["example4.com", "example5.com"],
        ]
        operation_type = "validation"
        results = []

        def acquire_domain_locks(thread_id, domains):
            try:
                with acquire_multi_domain_lock(domains, operation_type, timeout=2):
                    time.sleep(0.1)  # Simulate work
                    results.append(
                        {"thread_id": thread_id, "domains": domains, "status": "success"}
                    )
                    return True
            except Exception as e:
                results.append(
                    {
                        "thread_id": thread_id,
                        "domains": domains,
                        "status": "failed",
                        "error": type(e).__name__,
                    }
                )
                return False

        # Run concurrent domain lock attempts
        with ThreadPoolExecutor(max_workers=len(domains_sets)) as executor:
            futures = [
                executor.submit(acquire_domain_locks, i, domains)
                for i, domains in enumerate(domains_sets)
            ]

            completed = sum(1 for future in as_completed(futures) if future.result())

        # All should eventually succeed (non-overlapping domains run in parallel)
        assert len(results) == len(domains_sets)
        successful_results = [r for r in results if r["status"] == "success"]
        assert len(successful_results) == len(domains_sets)

    def test_file_operation_concurrency(self, tmp_path):
        """Test concurrent file operations."""
        test_file = tmp_path / "test_file.txt"
        num_threads = 20
        results = []

        def write_to_file(thread_id, content):
            try:
                self.file_manager.safe_write_file(
                    str(test_file), f"Content from thread {thread_id}: {content}", backup=True
                )
                results.append(f"thread_{thread_id}_write_success")
                return True
            except Exception as e:
                results.append(f"thread_{thread_id}_write_failed_{type(e).__name__}")
                return False

        # Run concurrent write operations
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(write_to_file, i, f"data_{i}") for i in range(num_threads)]

            completed = sum(1 for future in as_completed(futures) if future.result())

        # All writes should succeed (they're serialized by the file manager)
        assert len(results) == num_threads
        successful_results = [r for r in results if "success" in r]
        assert len(successful_results) == num_threads

        # File should exist and contain content from the last write
        assert test_file.exists()
        content = test_file.read_text()
        assert "Content from thread" in content

    @pytest.mark.parametrize("num_operations", [5, 10, 20])
    def test_concurrent_certificate_operations(self, num_operations):
        """Test concurrent certificate operations with mock API."""
        mock_api_client = MockZeroSSLAPIClient("test-api-key")
        cert_manager = MockCertificateManager(api_client=mock_api_client)

        operations = PERFORMANCE_TEST_DATA["concurrent_operations"][:num_operations]
        results = []

        def perform_certificate_operation(op_id, operation):
            try:
                domains = operation["domains"]
                validation_method = operation["validation_method"]

                # Create certificate
                create_result = cert_manager.create_certificate(
                    domains=domains, csr="mock-csr-content", validation_method=validation_method
                )

                # Validate certificate
                validate_result = cert_manager.validate_certificate(
                    create_result["certificate_id"], validation_method
                )

                # Download certificate
                download_result = cert_manager.download_certificate(create_result["certificate_id"])

                results.append(
                    {
                        "operation_id": op_id,
                        "status": "success",
                        "certificate_id": create_result["certificate_id"],
                    }
                )
                return True
            except Exception as e:
                results.append({"operation_id": op_id, "status": "failed", "error": str(e)})
                return False

        start_time = time.time()

        # Run concurrent certificate operations
        with ThreadPoolExecutor(max_workers=min(num_operations, 10)) as executor:
            futures = [
                executor.submit(perform_certificate_operation, i, op)
                for i, op in enumerate(operations)
            ]

            completed = sum(1 for future in as_completed(futures) if future.result())

        end_time = time.time()
        duration = end_time - start_time

        # Verify results
        assert len(results) == num_operations
        successful_results = [r for r in results if r["status"] == "success"]
        assert len(successful_results) == num_operations

        # Performance assertions (should complete within reasonable time)
        max_expected_duration = num_operations * 0.5  # 0.5 seconds per operation max
        assert duration < max_expected_duration, f"Operations took too long: {duration}s"

        print(f"Completed {num_operations} concurrent operations in {duration:.2f}s")


class TestRateLimiting:
    """Test API rate limiting behavior."""

    def test_rate_limit_tracking(self):
        """Test rate limit tracking in API client."""
        api_client = ZeroSSLAPIClient("test-api-key-1234567890123456")

        # Initial rate limit
        assert api_client.rate_limit_remaining == 5000

        # Mock response with rate limit headers
        mock_response = Mock()
        mock_response.headers = {"X-RateLimit-Remaining": "4999"}

        api_client._update_rate_limit_from_response(mock_response)
        assert api_client.rate_limit_remaining == 4999

    def test_rate_limit_with_mock_responses(self):
        """Test rate limiting with mock API responses."""
        from tests.fixtures.zerossl_responses import RATE_LIMIT_EXCEEDED_HEADERS, ERROR_RATE_LIMIT

        with patch("requests.Session") as mock_session_class:
            mock_session = Mock()
            mock_session_class.return_value = mock_session

            # First response succeeds
            success_response = Mock()
            success_response.status_code = 200
            success_response.json.return_value = {"id": "cert-123", "status": "draft"}
            success_response.headers = {"X-RateLimit-Remaining": "1"}

            # Second response hits rate limit
            rate_limit_response = Mock()
            rate_limit_response.status_code = 429
            rate_limit_response.json.return_value = ERROR_RATE_LIMIT
            rate_limit_response.headers = RATE_LIMIT_EXCEEDED_HEADERS

            mock_session.post.side_effect = [success_response, rate_limit_response]

            api_client = ZeroSSLAPIClient("test-api-key-1234567890123456")

            # First request should succeed
            result1 = api_client.create_certificate(["example.com"], "mock-csr")
            assert result1["id"] == "cert-123"
            assert api_client.rate_limit_remaining == 1

            # Second request should raise rate limit error
            from plugins.module_utils.zerossl.exceptions import ZeroSSLRateLimitError

            with pytest.raises(ZeroSSLRateLimitError):
                api_client.create_certificate(["example2.com"], "mock-csr")

    def test_rapid_api_calls_performance(self):
        """Test performance under rapid API calls."""
        mock_api_client = MockZeroSSLAPIClient("test-api-key")
        rapid_calls = PERFORMANCE_TEST_DATA["rapid_api_calls"]

        results = []
        start_time = time.time()

        for i, call_info in enumerate(rapid_calls):
            action = call_info["action"]
            delay = call_info["delay"]

            try:
                if action == "create":
                    result = mock_api_client.create_certificate(["example.com"], "mock-csr")
                elif action == "status":
                    result = mock_api_client.get_certificate("cert-123")
                elif action == "validate":
                    result = mock_api_client.validate_certificate("cert-123", "HTTP_CSR_HASH")
                elif action == "download":
                    result = mock_api_client.download_certificate("cert-123")

                results.append({"call_id": i, "action": action, "status": "success"})
                time.sleep(delay)
            except Exception as e:
                results.append(
                    {"call_id": i, "action": action, "status": "failed", "error": str(e)}
                )

        end_time = time.time()
        total_duration = end_time - start_time

        # All calls should succeed with mock client
        assert len(results) == len(rapid_calls)
        successful_calls = [r for r in results if r["status"] == "success"]
        assert len(successful_calls) == len(rapid_calls)

        # Performance check
        expected_duration = sum(call["delay"] for call in rapid_calls)
        assert total_duration >= expected_duration  # Should take at least the sum of delays

        print(f"Completed {len(rapid_calls)} rapid API calls in {total_duration:.2f}s")


class TestCachePerformance:
    """Test caching performance and efficiency."""

    def setup_method(self):
        """Setup for each test method."""
        from plugins.module_utils.zerossl.cache import CertificateCache

        # Create cache with higher max size for performance testing
        test_cache = CertificateCache(max_cache_size=2000)
        self.cache_manager = CertificateCacheManager(cache=test_cache)

    def test_cache_hit_performance(self):
        """Test cache hit performance."""
        certificate_id = "test-cert-123"
        test_data = {"status": "issued", "expires": "2025-04-15 10:30:00"}

        # Warm up the cache
        self.cache_manager.set_certificate_status(certificate_id, test_data)

        # Measure cache hit performance
        num_hits = 1000
        start_time = time.time()

        for _ in range(num_hits):
            result = self.cache_manager.get_certificate_status(certificate_id)
            assert result == test_data

        end_time = time.time()
        duration = end_time - start_time

        # Cache hits should be very fast
        avg_time_per_hit = duration / num_hits
        assert avg_time_per_hit < 0.001, f"Cache hits too slow: {avg_time_per_hit:.6f}s per hit"

        print(f"Average cache hit time: {avg_time_per_hit * 1000:.3f}ms")

    def test_concurrent_cache_operations(self):
        """Test concurrent cache operations."""
        num_threads = 20
        operations_per_thread = 100
        results = []

        def cache_operations(thread_id):
            try:
                local_results = []
                for i in range(operations_per_thread):
                    cert_id = f"cert-{thread_id}-{i}"
                    data = {"status": "issued", "thread_id": thread_id, "operation": i}

                    # Set and get operations
                    self.cache_manager.set_certificate_status(cert_id, data)
                    retrieved = self.cache_manager.get_certificate_status(cert_id)

                    if retrieved == data:
                        local_results.append("success")
                    else:
                        local_results.append("mismatch")

                results.extend(local_results)
                return len(local_results)
            except Exception as e:
                results.append(f"thread_{thread_id}_error_{type(e).__name__}")
                return 0

        start_time = time.time()

        # Run concurrent cache operations
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(cache_operations, i) for i in range(num_threads)]

            total_operations = sum(future.result() for future in as_completed(futures))

        end_time = time.time()
        duration = end_time - start_time

        # Verify all operations succeeded
        expected_operations = num_threads * operations_per_thread
        assert total_operations == expected_operations

        successful_operations = [r for r in results if r == "success"]
        assert len(successful_operations) == expected_operations

        # Performance check
        ops_per_second = total_operations / duration
        assert ops_per_second > 1000, f"Cache operations too slow: {ops_per_second:.0f} ops/sec"

        print(f"Concurrent cache performance: {ops_per_second:.0f} operations/second")

    def test_cache_memory_usage(self):
        """Test cache memory usage with large datasets."""
        import sys
        import gc

        # Measure initial memory
        gc.collect()
        initial_size = sys.getsizeof(self.cache_manager.cache._memory_cache)

        # Add many cache entries
        num_entries = 1000
        for i in range(num_entries):
            cert_id = f"cert-{i:04d}"
            data = {
                "status": "issued",
                "expires": "2025-04-15 10:30:00",
                "domains": [f"example{i}.com", f"www.example{i}.com"],
                "large_data": "x" * 1000,  # 1KB of data per entry
            }
            self.cache_manager.set_certificate_status(cert_id, data)

        # Measure memory after additions
        final_size = sys.getsizeof(self.cache_manager.cache._memory_cache)
        memory_growth = final_size - initial_size

        # Memory growth should be reasonable
        max_expected_growth = num_entries * 2000  # ~2KB per entry max
        assert memory_growth < max_expected_growth, f"Memory usage too high: {memory_growth} bytes"

        print(f"Memory usage for {num_entries} cache entries: {memory_growth} bytes")

        # Test cache cleanup
        stats = self.cache_manager.get_cache_statistics()
        assert stats["memory_entries"] == num_entries

        # Force cleanup
        self.cache_manager.cleanup_expired_entries()

        # Memory should be manageable
        final_stats = self.cache_manager.get_cache_statistics()
        assert final_stats["memory_entries"] <= num_entries


class TestPerformanceBenchmarks:
    """Comprehensive performance benchmarks."""

    def test_end_to_end_performance_benchmark(self, tmp_path):
        """Test end-to-end performance of certificate operations."""
        # Setup test environment
        test_dirs = create_test_file_structure(tmp_path)
        mock_api_client = MockZeroSSLAPIClient("test-api-key")
        cert_manager = MockCertificateManager(api_client=mock_api_client)

        operations = [
            {
                "domains": ["benchmark1.com"],
                "certificate_path": str(test_dirs["certs"] / "benchmark1.crt"),
                "private_key_path": str(test_dirs["private"] / "benchmark1.key"),
            },
            {
                "domains": ["benchmark2.com", "www.benchmark2.com"],
                "certificate_path": str(test_dirs["certs"] / "benchmark2.crt"),
                "private_key_path": str(test_dirs["private"] / "benchmark2.key"),
            },
            {
                "domains": ["*.benchmark3.com"],
                "certificate_path": str(test_dirs["certs"] / "benchmark3.crt"),
                "validation_method": "DNS_CSR_HASH",
            },
        ]

        results = []
        total_start_time = time.time()

        for i, operation in enumerate(operations):
            start_time = time.time()

            try:
                # Create certificate
                create_result = cert_manager.create_certificate(
                    domains=operation["domains"],
                    csr="mock-csr-content",
                    validation_method=operation.get("validation_method", "HTTP_CSR_HASH"),
                )

                # Validate certificate
                validate_result = cert_manager.validate_certificate(
                    create_result["certificate_id"],
                    operation.get("validation_method", "HTTP_CSR_HASH"),
                )

                # Download certificate
                download_result = cert_manager.download_certificate(create_result["certificate_id"])

                # Simulate file writing
                if operation.get("certificate_path"):
                    with open(operation["certificate_path"], "w") as f:
                        f.write(download_result["certificate"])

                if operation.get("private_key_path"):
                    with open(operation["private_key_path"], "w") as f:
                        f.write(download_result["private_key"])

                end_time = time.time()
                operation_duration = end_time - start_time

                results.append(
                    {
                        "operation_id": i,
                        "domains": operation["domains"],
                        "duration": operation_duration,
                        "status": "success",
                    }
                )

            except Exception as e:
                end_time = time.time()
                operation_duration = end_time - start_time

                results.append(
                    {
                        "operation_id": i,
                        "domains": operation["domains"],
                        "duration": operation_duration,
                        "status": "failed",
                        "error": str(e),
                    }
                )

        total_end_time = time.time()
        total_duration = total_end_time - total_start_time

        # Verify all operations succeeded
        successful_operations = [r for r in results if r["status"] == "success"]
        assert len(successful_operations) == len(operations)

        # Performance assertions
        max_operation_time = max(r["duration"] for r in results)
        avg_operation_time = sum(r["duration"] for r in results) / len(results)

        assert (
            max_operation_time < 1.0
        ), f"Slowest operation took too long: {max_operation_time:.2f}s"
        assert (
            avg_operation_time < 0.5
        ), f"Average operation time too high: {avg_operation_time:.2f}s"

        print(f"End-to-end benchmark results:")
        print(f"  Total time: {total_duration:.2f}s")
        print(f"  Average operation time: {avg_operation_time:.3f}s")
        print(f"  Max operation time: {max_operation_time:.3f}s")
        print(f"  Operations per second: {len(operations) / total_duration:.1f}")

        return {
            "total_duration": total_duration,
            "avg_operation_time": avg_operation_time,
            "max_operation_time": max_operation_time,
            "operations_per_second": len(operations) / total_duration,
        }
