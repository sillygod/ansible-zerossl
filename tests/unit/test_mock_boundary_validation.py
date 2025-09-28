# -*- coding: utf-8 -*-
"""
Mock Boundary Contract Validation.

This contract validation test ensures that tests only mock at appropriate
boundaries (HTTP, filesystem, external APIs) and avoid over-mocking of
internal business logic.
"""

import ast
import inspect
import importlib
import re
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple

import pytest


class MockBoundaryValidator:
    """Validates that tests mock only at appropriate boundaries."""

    def __init__(self):
        self.project_root = self._find_project_root()
        self.test_modules = {}
        self.source_modules = {}
        self._load_test_modules()
        self._load_source_modules()

        # Define allowed mock boundaries
        self.allowed_mock_targets = {
            # HTTP requests
            'requests.Session',
            'requests.get',
            'requests.post',
            'requests.put',
            'requests.delete',
            'requests.request',
            'requests.Session.get',
            'requests.Session.post',
            'requests.Session.put',
            'requests.Session.delete',
            'requests.Session.request',

            # File operations
            'open',
            'pathlib.Path.open',
            'pathlib.Path.exists',
            'pathlib.Path.write_text',
            'pathlib.Path.read_text',
            'os.path.exists',
            'os.makedirs',
            'shutil.copy2',
            'shutil.move',

            # Time operations (for testing timeouts/delays)
            'time.sleep',
            'time.time',
            'datetime.datetime.now',
            'datetime.datetime.utcnow',

            # External process execution
            'subprocess.run',
            'subprocess.Popen',

            # DNS operations (external network dependency)
            'dns.resolver.Resolver',
            'dns.resolver.resolve',
            'dns.query',
            'socket.gethostbyname',
            'socket.getaddrinfo',

            # Ansible-specific external boundaries
            'ansible.module_utils.basic.AnsibleModule',
            'ansible.plugins.action.ActionBase',

            # Test fixtures and data
            'tests.fixtures',
            'conftest'
        }

        # Internal business logic that should NOT be mocked
        self.forbidden_mock_targets = {
            'plugins.module_utils.zerossl.certificate_manager.CertificateManager.create_certificate',
            'plugins.module_utils.zerossl.certificate_manager.CertificateManager.get_certificate_status',
            'plugins.module_utils.zerossl.certificate_manager.CertificateManager.needs_renewal',
            'plugins.module_utils.zerossl.certificate_manager.CertificateManager.validate_certificate',
            'plugins.module_utils.zerossl.certificate_manager.CertificateManager.download_certificate',
            'plugins.module_utils.zerossl.api_client.ZeroSSLAPIClient.create_certificate',
            'plugins.module_utils.zerossl.api_client.ZeroSSLAPIClient.get_certificate',
            'plugins.module_utils.zerossl.validation_handler.ValidationHandler.prepare_http_validation',
            'plugins.action.zerossl_certificate.ActionModule._handle_present_state',
            'plugins.action.zerossl_certificate.ActionModule._handle_request_state',
        }

    def _find_project_root(self) -> Path:
        """Find the project root directory."""
        current = Path(__file__).parent
        while current.parent != current:
            if (current / 'pyproject.toml').exists():
                return current
            current = current.parent
        return Path.cwd()

    def _load_test_modules(self):
        """Load all test modules for analysis."""
        test_files = [
            'tests.unit.test_certificate_manager',
            'tests.unit.test_api_client',
            'tests.unit.test_plugin_contract',
            'tests.unit.test_validation_handler',
            'tests.unit.test_zerossl_api_contract',
            'tests.unit.test_zerossl_validation_contract',
            'tests.component.test_full_automation',
            'tests.component.test_error_handling',
            'tests.component.test_multi_domain',
            'tests.component.test_renewal_check',
            'tests.component.test_security',
            'tests.component.test_split_workflow',
            'tests.component.test_dns_validation',
        ]

        for module_name in test_files:
            try:
                module = importlib.import_module(module_name)
                self.test_modules[module_name] = module
            except ImportError:
                pass  # Module might not exist yet

    def _load_source_modules(self):
        """Load source modules to validate against."""
        try:
            from plugins.action.zerossl_certificate import ActionModule
            self.source_modules['ActionModule'] = ActionModule
        except ImportError:
            pass

        try:
            from plugins.module_utils.zerossl.certificate_manager import CertificateManager
            self.source_modules['CertificateManager'] = CertificateManager
        except ImportError:
            pass

        try:
            from plugins.module_utils.zerossl.api_client import ZeroSSLAPIClient
            self.source_modules['ZeroSSLAPIClient'] = ZeroSSLAPIClient
        except ImportError:
            pass

    def extract_mock_calls_from_test_file(self, test_file_path: str) -> List[Dict[str, Any]]:
        """Extract all mock-related calls from a test file."""
        mock_calls = []

        try:
            with open(test_file_path, 'r') as f:
                content = f.read()

            # Parse the AST
            tree = ast.parse(content)

            for node in ast.walk(tree):
                # Look for patch decorators
                if isinstance(node, ast.FunctionDef):
                    for decorator in node.decorator_list:
                        if isinstance(decorator, ast.Call):
                            if isinstance(decorator.func, ast.Attribute):
                                if decorator.func.attr == 'patch':
                                    # Extract the patch target
                                    if decorator.args:
                                        if isinstance(decorator.args[0], ast.Constant):
                                            target = decorator.args[0].value
                                            mock_calls.append({
                                                'type': 'patch_decorator',
                                                'target': target,
                                                'function': node.name,
                                                'line': node.lineno
                                            })

                # Look for patch context managers and direct calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        # patch.object calls
                        if node.func.attr in ['patch', 'patch_object']:
                            if node.args:
                                if isinstance(node.args[0], ast.Constant):
                                    target = node.args[0].value
                                elif isinstance(node.args[0], ast.Name):
                                    target = node.args[0].id
                                else:
                                    target = str(node.args[0])

                                mock_calls.append({
                                    'type': 'patch_call',
                                    'target': target,
                                    'line': node.lineno
                                })

                        # Mock object creation
                        elif node.func.attr in ['Mock', 'MagicMock']:
                            mock_calls.append({
                                'type': 'mock_creation',
                                'target': 'Mock object',
                                'line': node.lineno
                            })

                    # mocker.patch calls (pytest-mock)
                    elif isinstance(node.func, ast.Attribute):
                        if hasattr(node.func, 'value') and isinstance(node.func.value, ast.Name):
                            if node.func.value.id == 'mocker' and node.func.attr == 'patch':
                                if node.args and isinstance(node.args[0], ast.Constant):
                                    target = node.args[0].value
                                    mock_calls.append({
                                        'type': 'mocker_patch',
                                        'target': target,
                                        'line': node.lineno
                                    })

        except (SyntaxError, IOError) as e:
            pytest.fail(f"Failed to parse test file {test_file_path}: {e}")

        return mock_calls

    def analyze_mock_boundaries(self) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze all test files for mock boundary violations."""
        violations = {
            'forbidden_mocks': [],
            'suspicious_mocks': [],
            'boundary_violations': []
        }

        for module_name, test_module in self.test_modules.items():
            # Get the file path
            if hasattr(test_module, '__file__'):
                test_file_path = test_module.__file__
                mock_calls = self.extract_mock_calls_from_test_file(test_file_path)

                for mock_call in mock_calls:
                    target = mock_call['target']

                    # Check for forbidden mocks (internal business logic)
                    if self._is_forbidden_mock(target):
                        violations['forbidden_mocks'].append({
                            'module': module_name,
                            'target': target,
                            'type': mock_call['type'],
                            'line': mock_call.get('line'),
                            'reason': 'Internal business logic should not be mocked'
                        })

                    # Check for boundary violations
                    elif not self._is_allowed_mock_boundary(target):
                        violations['boundary_violations'].append({
                            'module': module_name,
                            'target': target,
                            'type': mock_call['type'],
                            'line': mock_call.get('line'),
                            'reason': 'Mock target not at allowed boundary'
                        })

                    # Check for suspicious mocks (might indicate over-mocking)
                    elif self._is_suspicious_mock(target):
                        violations['suspicious_mocks'].append({
                            'module': module_name,
                            'target': target,
                            'type': mock_call['type'],
                            'line': mock_call.get('line'),
                            'reason': 'Potentially over-mocking internal logic'
                        })

        return violations

    def _is_forbidden_mock(self, target: str) -> bool:
        """Check if a mock target is explicitly forbidden."""
        return target in self.forbidden_mock_targets

    def _is_allowed_mock_boundary(self, target: str) -> bool:
        """Check if a mock target is at an allowed boundary."""
        # Exact matches
        if target in self.allowed_mock_targets:
            return True

        # Pattern matches
        allowed_patterns = [
            r'^requests\.',
            r'^requests\.Session\.',
            r'\.open$',
            r'\.exists$',
            r'\.read$',
            r'\.write$',
            r'^time\.',
            r'^datetime\.',
            r'^os\.',
            r'^pathlib\.',
            r'^subprocess\.',
            r'tests\.fixtures',
            r'conftest\.',
            r'Mock$',  # Allow Mock objects themselves
        ]

        for pattern in allowed_patterns:
            if re.search(pattern, target):
                return True

        return False

    def _is_suspicious_mock(self, target: str) -> bool:
        """Check if a mock target might indicate over-mocking."""
        suspicious_patterns = [
            r'plugins\.module_utils\.zerossl\.',  # Internal modules
            r'\._[^_]',  # Private methods (but not dunder methods)
            r'\.validate_',  # Validation methods (business logic)
            r'\.process_',  # Processing methods (business logic)
            r'\.handle_',  # Handler methods (business logic)
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, target) and not self._is_allowed_mock_boundary(target):
                return True

        return False

    def find_tests_using_real_methods(self) -> Dict[str, List[str]]:
        """Find tests that properly exercise real methods without mocking."""
        real_method_tests = {}

        for module_name, test_module in self.test_modules.items():
            test_methods = []

            # Check module-level test functions
            for name in dir(test_module):
                if name.startswith('test_'):
                    test_func = getattr(test_module, name)
                    if callable(test_func):
                        # Analyze if this test uses real methods
                        if self._test_uses_real_methods(test_func):
                            test_methods.append(name)

                # Check test classes
                elif name.startswith('Test') and hasattr(test_module, name):
                    test_class = getattr(test_module, name)
                    if inspect.isclass(test_class):
                        # Look for test methods in the class
                        for method_name in dir(test_class):
                            if method_name.startswith('test_'):
                                test_method = getattr(test_class, method_name)
                                if callable(test_method):
                                    # Analyze if this test uses real methods
                                    if self._test_uses_real_methods(test_method):
                                        test_methods.append(f"{name}.{method_name}")

            if test_methods:
                real_method_tests[module_name] = test_methods

        return real_method_tests

    def _test_uses_real_methods(self, test_func) -> bool:
        """Check if a test function exercises real methods."""
        try:
            source = inspect.getsource(test_func)

            # Look for signs that this test uses real objects
            real_usage_indicators = [
                'CertificateManager(',  # Direct instantiation
                'ZeroSSLAPIClient(',    # Direct instantiation
                'ActionModule(',        # Direct instantiation
                '.create_certificate(',  # Method calls on real objects
                '.get_certificate_status(',
                '.needs_renewal(',
            ]

            # Look for absence of excessive mocking
            excessive_mocking_indicators = [
                'patch.object(',
                'mock_',
                '.side_effect',
                '.return_value',
            ]

            has_real_usage = any(indicator in source for indicator in real_usage_indicators)
            has_minimal_mocking = sum(1 for indicator in excessive_mocking_indicators
                                    if indicator in source) <= 2

            return has_real_usage and has_minimal_mocking

        except Exception:
            return False


@pytest.mark.unit
class TestMockBoundaryValidation:
    """Contract validation tests for mock boundaries."""

    def test_no_forbidden_internal_mocking(self):
        """
        CONTRACT: Tests must not mock internal business logic methods.

        This test ensures that tests exercise real business logic rather than
        mocking core functionality like certificate creation, validation, etc.
        """
        validator = MockBoundaryValidator()
        violations = validator.analyze_mock_boundaries()

        forbidden_mocks = violations['forbidden_mocks']

        if forbidden_mocks:
            error_messages = []
            for violation in forbidden_mocks:
                error_messages.append(
                    f"  {violation['module']}: Mocking forbidden target '{violation['target']}' "
                    f"(line {violation.get('line', 'unknown')})"
                )

            pytest.fail(
                f"Found {len(forbidden_mocks)} forbidden internal mock(s):\n" +
                '\n'.join(error_messages) +
                "\n\nThese methods should be tested directly, not mocked."
            )

    def test_mocking_only_at_allowed_boundaries(self):
        """
        CONTRACT: All mocking must occur at allowed boundaries (HTTP, filesystem, external APIs).

        This test ensures that mocking is limited to infrastructure boundaries
        and doesn't interfere with testing actual business logic.
        """
        validator = MockBoundaryValidator()
        violations = validator.analyze_mock_boundaries()

        boundary_violations = violations['boundary_violations']

        if boundary_violations:
            error_messages = []
            for violation in boundary_violations:
                error_messages.append(
                    f"  {violation['module']}: Invalid mock boundary '{violation['target']}' "
                    f"(line {violation.get('line', 'unknown')})"
                )

            pytest.fail(
                f"Found {len(boundary_violations)} mock boundary violation(s):\n" +
                '\n'.join(error_messages) +
                "\n\nOnly mock at HTTP, filesystem, or external API boundaries."
            )

    def test_minimal_over_mocking_detected(self):
        """
        CONTRACT: Tests should have minimal mocking and focus on real code paths.

        This test warns about suspicious mocking patterns that might indicate
        over-mocking of internal logic.
        """
        validator = MockBoundaryValidator()
        violations = validator.analyze_mock_boundaries()

        suspicious_mocks = violations['suspicious_mocks']

        if suspicious_mocks:
            # During development, report suspicious mocks as warnings
            warning_messages = []
            for violation in suspicious_mocks:
                warning_messages.append(
                    f"  {violation['module']}: Suspicious mock '{violation['target']}' "
                    f"(line {violation.get('line', 'unknown')})"
                )

            pytest.warns(
                UserWarning,
                match="Suspicious mocking patterns detected"
            )

            print(
                f"\nWarning: {len(suspicious_mocks)} suspicious mock pattern(s) detected:\n" +
                '\n'.join(warning_messages) +
                "\n\nConsider testing these methods directly instead of mocking."
            )

    def test_http_boundary_mocking_is_consistent(self):
        """
        CONTRACT: HTTP mocking must be consistent and use approved patterns.

        This test ensures that HTTP mocking follows the established patterns
        using pytest-mock and mocks only requests.Session calls.
        """
        validator = MockBoundaryValidator()

        # Check that HTTP mocking follows consistent patterns
        http_mock_violations = []

        for module_name, test_module in validator.test_modules.items():
            if hasattr(test_module, '__file__'):
                mock_calls = validator.extract_mock_calls_from_test_file(test_module.__file__)

                for mock_call in mock_calls:
                    target = mock_call['target']

                    # Check for inconsistent HTTP mocking patterns
                    if 'requests' in target and target not in validator.allowed_mock_targets:
                        # Check if it's using the approved Session-based mocking
                        if not any(approved in target for approved in ['Session', 'session']):
                            http_mock_violations.append({
                                'module': module_name,
                                'target': target,
                                'line': mock_call.get('line'),
                                'reason': 'Should mock requests.Session instead of direct requests methods'
                            })

        if http_mock_violations:
            error_messages = []
            for violation in http_mock_violations:
                error_messages.append(
                    f"  {violation['module']}: {violation['target']} "
                    f"(line {violation.get('line', 'unknown')}): {violation['reason']}"
                )

            pytest.fail(
                f"Found {len(http_mock_violations)} HTTP mocking pattern violation(s):\n" +
                '\n'.join(error_messages)
            )

    def test_tests_exercise_real_code_paths(self):
        """
        CONTRACT: Tests must exercise real code paths with minimal mocking.

        This test ensures that there are tests that actually call real methods
        and exercise business logic rather than just testing mocked interactions.
        """
        validator = MockBoundaryValidator()
        real_method_tests = validator.find_tests_using_real_methods()

        if not real_method_tests:
            pytest.fail(
                "No tests found that exercise real code paths. "
                "Tests should call actual methods with minimal mocking."
            )

        # Ensure key modules have real method tests
        required_modules_with_real_tests = [
            'tests.unit.test_certificate_manager',
            'tests.unit.test_api_client',
            'tests.component.test_full_automation'
        ]

        missing_real_tests = []
        for required_module in required_modules_with_real_tests:
            if required_module not in real_method_tests:
                missing_real_tests.append(required_module)

        if missing_real_tests:
            pytest.fail(
                f"These critical modules lack tests that exercise real code paths: "
                f"{missing_real_tests}"
            )

    def test_fixture_based_mocking_is_preferred(self):
        """
        CONTRACT: Mocking should use fixture-based patterns for consistency.

        This test ensures that mocking follows fixture-based patterns
        rather than ad-hoc patching in individual test methods.
        """
        validator = MockBoundaryValidator()

        fixture_violations = []

        for module_name, test_module in validator.test_modules.items():
            if hasattr(test_module, '__file__'):
                mock_calls = validator.extract_mock_calls_from_test_file(test_module.__file__)

                # Count patch decorators vs fixture-based mocking
                patch_decorators = [call for call in mock_calls if call['type'] == 'patch_decorator']
                mocker_patches = [call for call in mock_calls if call['type'] == 'mocker_patch']

                # If there are many patch decorators but few fixture-based mocks, flag it
                if len(patch_decorators) > 3 and len(mocker_patches) == 0:
                    fixture_violations.append({
                        'module': module_name,
                        'patch_count': len(patch_decorators),
                        'reason': 'Consider using fixture-based mocking (pytest-mock) for consistency'
                    })

        # This is a recommendation, not a hard failure
        if fixture_violations:
            warning_messages = []
            for violation in fixture_violations:
                warning_messages.append(
                    f"  {violation['module']}: {violation['patch_count']} patch decorators - "
                    f"{violation['reason']}"
                )

            pytest.warns(
                UserWarning,
                match="Consider fixture-based mocking patterns"
            )

            print(
                f"\nRecommendation: Consider fixture-based mocking in {len(fixture_violations)} module(s):\n" +
                '\n'.join(warning_messages)
            )

    def test_mock_boundary_documentation_exists(self):
        """
        CONTRACT: Mock boundary decisions must be documented.

        This test ensures that the project has clear documentation about
        what should and should not be mocked.
        """
        validator = MockBoundaryValidator()

        # Check for documentation in common locations
        docs_locations = [
            validator.project_root / 'README.md',
            validator.project_root / 'docs' / 'testing.md',
            validator.project_root / 'tests' / 'README.md',
            validator.project_root / 'TESTING.md',
        ]

        mock_documentation_found = False
        for doc_path in docs_locations:
            if doc_path.exists():
                try:
                    with open(doc_path, 'r') as f:
                        content = f.read().lower()

                    if any(keyword in content for keyword in [
                        'mock', 'boundary', 'test', 'http', 'requests'
                    ]):
                        mock_documentation_found = True
                        break
                except IOError:
                    continue

        # Also check for inline documentation in conftest.py
        conftest_path = validator.project_root / 'tests' / 'conftest.py'
        if conftest_path.exists():
            try:
                with open(conftest_path, 'r') as f:
                    content = f.read()

                if 'mock' in content.lower() and ('boundary' in content.lower() or 'http' in content.lower()):
                    mock_documentation_found = True
            except IOError:
                pass

        if not mock_documentation_found:
            pytest.fail(
                "No mock boundary documentation found. "
                "Please document what should and should not be mocked."
            )
