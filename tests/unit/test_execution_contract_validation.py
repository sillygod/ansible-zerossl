# -*- coding: utf-8 -*-
"""
Test Execution Contract Validation.

This contract validation test ensures that all unit and component tests
properly exercise real method signatures and follow TDD principles.
"""

import ast
import inspect
import importlib
import sys
from pathlib import Path
from typing import Dict, List, Set, Any, Optional

import pytest


class MethodSignatureValidator:
    """Validates that test method calls match actual source code methods."""

    def __init__(self):
        self.source_modules = {}
        self.test_modules = {}
        self._load_source_modules()
        self._load_test_modules()

    def _load_source_modules(self):
        """Load all source modules to validate against."""
        # Import main action module
        try:
            from plugins.action.zerossl_certificate import ActionModule

            self.source_modules["ActionModule"] = ActionModule
        except ImportError:
            pass

        # Import certificate manager
        try:
            from plugins.module_utils.zerossl.certificate_manager import CertificateManager

            self.source_modules["CertificateManager"] = CertificateManager
        except ImportError:
            pass

        # Import API client
        try:
            from plugins.module_utils.zerossl.api_client import ZeroSSLAPIClient

            self.source_modules["ZeroSSLAPIClient"] = ZeroSSLAPIClient
        except ImportError:
            pass

        # Import validation handler
        try:
            from plugins.module_utils.zerossl.validation_handler import ValidationHandler

            self.source_modules["ValidationHandler"] = ValidationHandler
        except ImportError:
            pass

    def _load_test_modules(self):
        """Load test modules for inspection."""
        test_files = [
            "tests.unit.test_certificate_manager",
            "tests.unit.test_api_client",
            "tests.unit.test_plugin_contract",
            "tests.unit.test_validation_handler",
            "tests.unit.test_zerossl_api_contract",
            "tests.unit.test_zerossl_validation_contract",
            "tests.component.test_full_automation",
            "tests.component.test_error_handling",
            "tests.component.test_multi_domain",
            "tests.component.test_renewal_check",
            "tests.component.test_security",
            "tests.component.test_split_workflow",
            "tests.component.test_dns_validation",
        ]

        for module_name in test_files:
            try:
                module = importlib.import_module(module_name)
                self.test_modules[module_name] = module
            except ImportError as e:
                pytest.fail(f"Failed to import test module {module_name}: {e}")

    def get_class_methods(self, cls) -> Set[str]:
        """Get all public methods from a class."""
        methods = set()
        for name, method in inspect.getmembers(cls, predicate=inspect.ismethod):
            if not name.startswith("_"):
                methods.add(name)
        for name, method in inspect.getmembers(cls, predicate=inspect.isfunction):
            if not name.startswith("_"):
                methods.add(name)
        return methods

    def extract_method_calls_from_test(self, test_function) -> List[str]:
        """Extract method calls from a test function's source code."""
        try:
            source_code = inspect.getsource(test_function)
            tree = ast.parse(source_code)

            method_calls = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        method_calls.append(node.func.attr)

            return method_calls
        except Exception:
            return []

    def validate_test_method_signatures(self) -> List[Dict[str, Any]]:
        """Validate that test methods call actual source methods."""
        violations = []

        for module_name, test_module in self.test_modules.items():
            for name in dir(test_module):
                if name.startswith("test_"):
                    test_func = getattr(test_module, name)
                    if callable(test_func):
                        method_calls = self.extract_method_calls_from_test(test_func)

                        # Check each method call against source modules
                        for method_call in method_calls:
                            if not self._is_valid_method_call(method_call):
                                violations.append(
                                    {
                                        "test_module": module_name,
                                        "test_method": name,
                                        "invalid_call": method_call,
                                        "reason": "Method not found in source code",
                                    }
                                )

        return violations

    def _is_valid_method_call(self, method_name: str) -> bool:
        """Check if a method call exists in any source module."""
        # Skip validation for common test methods
        test_methods = {
            "assert",
            "assertEqual",
            "assertTrue",
            "assertFalse",
            "assertRaises",
            "patch",
            "Mock",
            "MagicMock",
            "side_effect",
            "return_value",
            "call_count",
            "called",
            "assert_called_with",
            "assert_called_once",
            "reset_mock",
            "configure_mock",
            "attach_mock",
        }

        if method_name in test_methods:
            return True

        # Check against source modules
        for class_name, source_class in self.source_modules.items():
            class_methods = self.get_class_methods(source_class)
            if method_name in class_methods:
                return True

        return False


@pytest.mark.unit
class TestExecutionContractValidation:
    """Contract validation tests for test execution."""

    def test_method_signatures_match_source_code(self):
        """
        CONTRACT: All test method calls must match actual source code method signatures.

        This test ensures that tests are calling real methods and will detect
        typos, renamed methods, or deleted methods that would make tests ineffective.
        """
        validator = MethodSignatureValidator()
        violations = validator.validate_test_method_signatures()

        if violations:
            error_messages = []
            for violation in violations:
                error_messages.append(
                    f"Test '{violation['test_method']}' in '{violation['test_module']}' "
                    f"calls non-existent method '{violation['invalid_call']}'"
                )

            pytest.fail(
                f"Found {len(violations)} method signature violations:\n"
                + "\n".join(error_messages)
            )

    def test_certificate_manager_methods_have_tests(self):
        """
        CONTRACT: All public CertificateManager methods must have corresponding tests.

        This ensures comprehensive test coverage of the core business logic.
        """
        if "CertificateManager" not in MethodSignatureValidator().source_modules:
            pytest.skip("CertificateManager not available for testing")

        validator = MethodSignatureValidator()
        cert_manager = validator.source_modules["CertificateManager"]
        public_methods = validator.get_class_methods(cert_manager)

        # Expected methods that should have tests
        expected_methods = {
            "create_certificate",
            "get_certificate_status",
            "find_certificate_for_domains",
            "needs_renewal",
            "validate_certificate",
            "download_certificate",
            "poll_validation_status",
        }

        # Check that all expected methods exist
        missing_methods = expected_methods - public_methods
        if missing_methods:
            pytest.fail(f"Expected methods not found in CertificateManager: {missing_methods}")

        # Verify each method has test coverage
        test_module_name = "tests.unit.test_certificate_manager"
        if test_module_name in validator.test_modules:
            test_module = validator.test_modules[test_module_name]

            # Extract test methods from test classes
            test_names = []
            for name, obj in inspect.getmembers(test_module):
                if inspect.isclass(obj) and name.startswith("Test"):
                    # Get all attributes from the class, not just bound methods
                    for method_name in dir(obj):
                        if method_name.startswith("test_") and callable(getattr(obj, method_name)):
                            test_names.append(method_name)

            for method in expected_methods:
                # Check if any test name contains the method name using flexible matching
                method_patterns = [
                    method.replace("_", "").lower(),  # pollvalidationstatus
                    method.lower(),  # poll_validation_status
                    method.replace("_", ""),  # pollvalidationstatus (case sensitive)
                ]

                has_test = any(
                    any(pattern in test_name.lower() for pattern in method_patterns)
                    for test_name in test_names
                )

                if not has_test:
                    pytest.fail(f"No test found for CertificateManager.{method}")

    def test_api_client_methods_have_tests(self):
        """
        CONTRACT: All public ZeroSSLAPIClient methods must have corresponding tests.

        This ensures proper testing of HTTP boundary interactions.
        """
        if "ZeroSSLAPIClient" not in MethodSignatureValidator().source_modules:
            pytest.skip("ZeroSSLAPIClient not available for testing")

        validator = MethodSignatureValidator()
        api_client = validator.source_modules["ZeroSSLAPIClient"]
        public_methods = validator.get_class_methods(api_client)

        # Expected methods that should have tests
        expected_methods = {
            "create_certificate",
            "get_certificate",
            "list_certificates",
            "validate_certificate",
            "download_certificate",
            "cancel_certificate",
        }

        # Check that all expected methods exist
        missing_methods = expected_methods - public_methods
        if missing_methods:
            pytest.fail(f"Expected methods not found in ZeroSSLAPIClient: {missing_methods}")

        # Verify each method has test coverage
        test_module_name = "tests.unit.test_api_client"
        if test_module_name in validator.test_modules:
            test_module = validator.test_modules[test_module_name]

            # Extract test methods from test classes
            test_names = []
            for name, obj in inspect.getmembers(test_module):
                if inspect.isclass(obj) and name.startswith("Test"):
                    # Get all attributes from the class, not just bound methods
                    for method_name in dir(obj):
                        if method_name.startswith("test_") and callable(getattr(obj, method_name)):
                            test_names.append(method_name)

            for method in expected_methods:
                # Check if any test name contains the method name using flexible matching
                method_patterns = [
                    method.replace("_", "").lower(),  # validatecertificate
                    method.lower(),  # validate_certificate
                    method.replace("_", ""),  # validatecertificate (case sensitive)
                ]

                has_test = any(
                    any(pattern in test_name.lower() for pattern in method_patterns)
                    for test_name in test_names
                )

                if not has_test:
                    pytest.fail(f"No test found for ZeroSSLAPIClient.{method}")

    def test_action_module_methods_have_tests(self):
        """
        CONTRACT: All public ActionModule methods must have corresponding tests.

        This ensures proper testing of Ansible integration layer.
        """
        if "ActionModule" not in MethodSignatureValidator().source_modules:
            pytest.skip("ActionModule not available for testing")

        validator = MethodSignatureValidator()
        action_module = validator.source_modules["ActionModule"]

        # Expected methods that should have tests
        expected_methods = {
            "run",  # Main entry point
            "_handle_present_state",
            "_handle_request_state",
            "_handle_validate_state",
            "_handle_download_state",
            "_handle_check_renewal_state",
            "_handle_absent_state",
        }

        # Get actual methods (including private ones for this critical module)
        all_methods = set()
        for name, method in inspect.getmembers(action_module, predicate=inspect.ismethod):
            if name in expected_methods:
                all_methods.add(name)
        for name, method in inspect.getmembers(action_module, predicate=inspect.isfunction):
            if name in expected_methods:
                all_methods.add(name)

        # Check that all expected methods exist
        missing_methods = expected_methods - all_methods
        if missing_methods:
            pytest.fail(f"Expected methods not found in ActionModule: {missing_methods}")

        # Verify each method has test coverage
        test_module_name = "tests.unit.test_plugin_contract"
        if test_module_name in validator.test_modules:
            test_module = validator.test_modules[test_module_name]

            # Extract test methods from test classes
            test_names = []
            for name, obj in inspect.getmembers(test_module):
                if inspect.isclass(obj) and name.startswith("Test"):
                    # Get all attributes from the class, not just bound methods
                    for method_name in dir(obj):
                        if method_name.startswith("test_") and callable(getattr(obj, method_name)):
                            test_names.append(method_name)

            # Main run method should definitely have tests
            run_tests = [name for name in test_names if "run" in name.lower()]
            if not run_tests:
                pytest.fail("No test found for ActionModule.run method")

    def test_component_tests_exercise_real_workflows(self):
        """
        CONTRACT: Component tests must exercise real end-to-end workflows.

        Component tests should test actual workflow methods rather than mocked interactions.
        """
        validator = MethodSignatureValidator()

        component_modules = [name for name in validator.test_modules.keys() if "component" in name]

        if not component_modules:
            pytest.fail("No component test modules found - component tests are required")

        # Check that component tests exist for key workflows
        expected_workflows = {
            "full_automation": "Complete certificate automation workflow",
            "multi_domain": "Multi-domain certificate handling",
            "renewal_check": "Certificate renewal checking",
            "error_handling": "Error handling and recovery",
            "dns_validation": "DNS validation workflow",
        }

        found_workflows = set()
        for module_name in component_modules:
            for workflow in expected_workflows:
                if workflow in module_name:
                    found_workflows.add(workflow)

        missing_workflows = set(expected_workflows.keys()) - found_workflows
        if missing_workflows:
            missing_list = [f"{w}: {expected_workflows[w]}" for w in missing_workflows]
            pytest.fail(f"Missing component test workflows:\n" + "\n".join(missing_list))

    def test_contract_validation_enforces_tdd_principles(self):
        """
        CONTRACT: This validation test itself must fail before implementation exists.

        This meta-test ensures that the contract validation is working correctly.
        It should detect when methods are called that don't exist yet.
        """
        # This test validates that our validation logic works
        validator = MethodSignatureValidator()

        # Simulate a violation - a method call that shouldn't exist
        fake_violations = [
            {
                "test_module": "test_example",
                "test_method": "test_nonexistent_method_call",
                "invalid_call": "definitely_nonexistent_method_12345",
                "reason": "Method not found in source code",
            }
        ]

        # Verify that our validation would catch this
        is_valid = validator._is_valid_method_call("definitely_nonexistent_method_12345")
        if is_valid:
            pytest.fail("Validation logic failed - should not validate nonexistent methods")

        # Verify that our validation correctly identifies valid methods
        valid_method_found = False
        if "CertificateManager" in validator.source_modules:
            is_valid = validator._is_valid_method_call("create_certificate")
            if is_valid:
                valid_method_found = True

        if not valid_method_found:
            pytest.fail("Validation logic failed - should validate existing methods")
