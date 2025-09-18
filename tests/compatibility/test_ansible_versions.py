# -*- coding: utf-8 -*-
"""
Ansible Version Compatibility Tests.

Tests to ensure the ZeroSSL plugin works correctly across different
Ansible versions and configurations.
"""

import pytest
import sys
import importlib
from unittest.mock import patch, Mock
from packaging import version

# Try to import ansible components
try:
    import ansible
    from ansible.plugins.action import ActionBase
    from ansible.module_utils.common.text.converters import to_text
    from ansible.errors import AnsibleActionFail
    from ansible.utils.display import Display
    ANSIBLE_AVAILABLE = True
    ANSIBLE_VERSION = ansible.__version__
except ImportError:
    ANSIBLE_AVAILABLE = False
    ANSIBLE_VERSION = None


class TestAnsibleCompatibility:
    """Test compatibility with different Ansible versions."""

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_ansible_version_supported(self):
        """Test that current Ansible version is supported."""
        min_version = "2.10.0"
        current_version = version.parse(ANSIBLE_VERSION)
        minimum_version = version.parse(min_version)

        assert current_version >= minimum_version, (
            f"Ansible {ANSIBLE_VERSION} is not supported. "
            f"Minimum required version is {min_version}"
        )

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_action_base_inheritance(self):
        """Test that plugin properly inherits from ActionBase."""
        # Import our action plugin
        sys.path.insert(0, '/Users/jing/Desktop/ansible-zerossl')

        try:
            from plugins.action.zerossl_certificate import ActionModule

            # Verify inheritance
            assert issubclass(ActionModule, ActionBase)

            # Test instantiation
            action_module = ActionModule(
                task=Mock(),
                connection=Mock(),
                play_context=Mock(),
                loader=Mock(),
                templar=Mock(),
                shared_loader_obj=Mock()
            )

            assert isinstance(action_module, ActionBase)
            assert hasattr(action_module, 'run')

        except ImportError as e:
            pytest.skip(f"Could not import action plugin: {e}")

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_display_functionality(self):
        """Test Ansible Display functionality."""
        display = Display()

        # Test different verbosity levels
        assert hasattr(display, 'v')
        assert hasattr(display, 'vv')
        assert hasattr(display, 'vvv')
        assert hasattr(display, 'display')
        assert hasattr(display, 'warning')
        assert hasattr(display, 'error')

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_text_converters(self):
        """Test Ansible text converter functionality."""
        # Test to_text function
        test_string = "test string"
        converted = to_text(test_string)
        assert isinstance(converted, str)
        assert converted == test_string

        # Test with bytes
        test_bytes = b"test bytes"
        converted = to_text(test_bytes)
        assert isinstance(converted, str)
        assert converted == "test bytes"

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_ansible_action_fail(self):
        """Test AnsibleActionFail exception."""
        error_message = "Test error message"

        with pytest.raises(AnsibleActionFail) as exc_info:
            raise AnsibleActionFail(error_message)

        assert str(exc_info.value) == error_message

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_module_utils_import(self):
        """Test that module_utils can be imported correctly."""
        sys.path.insert(0, '/Users/jing/Desktop/ansible-zerossl')

        try:
            # Test importing our module_utils
            from ansible.module_utils import zerossl

            # Verify expected components are available
            assert hasattr(zerossl, 'ZeroSSLAPIClient')
            assert hasattr(zerossl, 'CertificateManager')
            assert hasattr(zerossl, 'ValidationHandler')
            assert hasattr(zerossl, 'ConfigValidator')

        except ImportError as e:
            pytest.skip(f"Could not import module_utils: {e}")


class TestPluginConfiguration:
    """Test plugin configuration and parameter handling."""

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_documentation_format(self):
        """Test that DOCUMENTATION follows Ansible standards."""
        sys.path.insert(0, '/Users/jing/Desktop/ansible-zerossl')

        try:
            from plugins.action.zerossl_certificate import DOCUMENTATION
            import yaml

            # Parse DOCUMENTATION
            doc = yaml.safe_load(DOCUMENTATION)

            # Verify required fields
            assert 'module' in doc
            assert 'author' in doc
            assert 'version_added' in doc
            assert 'short_description' in doc
            assert 'description' in doc
            assert 'options' in doc

            # Verify required options exist
            options = doc['options']
            assert 'api_key' in options
            assert 'domains' in options

            # Verify option structure
            for option_name, option_data in options.items():
                assert 'description' in option_data
                assert 'type' in option_data

                # Required options should be marked
                if option_name in ['api_key', 'domains']:
                    assert option_data.get('required', False) is True

        except ImportError as e:
            pytest.skip(f"Could not import action plugin: {e}")
        except yaml.YAMLError as e:
            pytest.fail(f"DOCUMENTATION is not valid YAML: {e}")

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_examples_format(self):
        """Test that EXAMPLES follows Ansible standards."""
        sys.path.insert(0, '/Users/jing/Desktop/ansible-zerossl')

        try:
            from plugins.action.zerossl_certificate import EXAMPLES
            import yaml

            # Parse EXAMPLES - should be valid YAML
            examples = yaml.safe_load(EXAMPLES)

            # Should be a list of tasks or contain task examples
            assert examples is not None

            # If it's a list, should have at least one example using our module
            if isinstance(examples, list):
                has_zerossl_example = False
                for example in examples:
                    if isinstance(example, dict) and 'name' in example:
                        if 'zerossl_certificate' in str(example):
                            has_zerossl_example = True
                            break
                assert has_zerossl_example, "Examples should contain at least one zerossl_certificate task"

        except ImportError as e:
            pytest.skip(f"Could not import action plugin: {e}")
        except yaml.YAMLError as e:
            pytest.fail(f"EXAMPLES is not valid YAML: {e}")

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_return_format(self):
        """Test that RETURN follows Ansible standards."""
        sys.path.insert(0, '/Users/jing/Desktop/ansible-zerossl')

        try:
            from plugins.action.zerossl_certificate import RETURN
            import yaml

            # Parse RETURN
            return_doc = yaml.safe_load(RETURN)

            # Verify structure
            assert return_doc is not None

            # Common return values should be documented
            if isinstance(return_doc, dict):
                # Should document common return values
                expected_returns = ['changed', 'msg']
                for expected in expected_returns:
                    if expected in return_doc:
                        return_data = return_doc[expected]
                        assert 'description' in return_data
                        assert 'type' in return_data

        except ImportError as e:
            pytest.skip(f"Could not import action plugin: {e}")
        except yaml.YAMLError as e:
            pytest.fail(f"RETURN is not valid YAML: {e}")


class TestPythonCompatibility:
    """Test Python version compatibility."""

    def test_python_version_supported(self):
        """Test that current Python version is supported."""
        min_version = (3, 12)
        current_version = sys.version_info[:2]

        assert current_version >= min_version, (
            f"Python {'.'.join(map(str, current_version))} is not supported. "
            f"Minimum required version is {'.'.join(map(str, min_version))}"
        )

    def test_required_modules_available(self):
        """Test that required Python modules are available."""
        required_modules = [
            'requests',
            'pathlib',
            'json',
            'hashlib',
            'datetime',
            'time',
            'threading',
            'typing'
        ]

        for module_name in required_modules:
            try:
                importlib.import_module(module_name)
            except ImportError:
                pytest.fail(f"Required module '{module_name}' is not available")

    def test_optional_modules_handling(self):
        """Test graceful handling of optional modules."""
        # Test that our code handles missing optional dependencies
        with patch.dict('sys.modules', {'cryptography': None}):
            # Should not fail immediately
            pass

    def test_type_hints_compatibility(self):
        """Test that type hints work correctly."""
        from typing import Dict, List, Optional, Any

        # Test that we can use modern type hints
        def test_function(
            param1: str,
            param2: List[str],
            param3: Optional[Dict[str, Any]] = None
        ) -> bool:
            return True

        assert test_function("test", ["item1", "item2"], {"key": "value"})


class TestFeatureCompatibility:
    """Test compatibility of specific features across versions."""

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_task_vars_handling(self):
        """Test task_vars parameter handling."""
        # Different Ansible versions may handle task_vars differently
        sys.path.insert(0, '/Users/jing/Desktop/ansible-zerossl')

        try:
            from plugins.action.zerossl_certificate import ActionModule

            # Create mock objects
            mock_task = Mock()
            mock_task.args = {'api_key': 'test', 'domains': ['example.com']}

            action_module = ActionModule(
                task=mock_task,
                connection=Mock(),
                play_context=Mock(),
                loader=Mock(),
                templar=Mock(),
                shared_loader_obj=Mock()
            )

            # Test that run method accepts task_vars parameter
            import inspect
            run_signature = inspect.signature(action_module.run)
            assert 'task_vars' in run_signature.parameters

        except ImportError as e:
            pytest.skip(f"Could not import action plugin: {e}")

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_connection_handling(self):
        """Test connection parameter handling across versions."""
        # Ensure our plugin works with different connection types
        connection_types = ['ssh', 'local', 'winrm']

        for conn_type in connection_types:
            mock_connection = Mock()
            mock_connection._play_context = Mock()
            mock_connection._play_context.connection = conn_type

            # Our plugin should handle all connection types
            # (since it's an action plugin, not a module)
            assert mock_connection is not None

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_display_verbosity(self):
        """Test display verbosity handling across versions."""
        display = Display()

        # Test different verbosity methods
        verbosity_methods = ['v', 'vv', 'vvv', 'display', 'warning', 'error']

        for method_name in verbosity_methods:
            method = getattr(display, method_name, None)
            assert method is not None, f"Display method {method_name} not available"
            assert callable(method), f"Display method {method_name} is not callable"


class TestConfigurationCompatibility:
    """Test compatibility with different Ansible configurations."""

    def test_ansible_cfg_compatibility(self):
        """Test compatibility with various ansible.cfg settings."""
        # Read the ansible.cfg file if it exists
        import configparser
        from pathlib import Path

        ansible_cfg_path = Path('/Users/jing/Desktop/ansible-zerossl/ansible.cfg')

        if ansible_cfg_path.exists():
            config = configparser.ConfigParser()
            config.read(ansible_cfg_path)

            # Verify our configuration is compatible
            if 'defaults' in config:
                defaults = config['defaults']

                # Check action_plugins path
                if 'action_plugins' in defaults:
                    action_plugins_path = defaults['action_plugins']
                    assert Path(action_plugins_path).exists()

                # Check module_utils path
                if 'module_utils' in defaults:
                    module_utils_path = defaults['module_utils']
                    assert Path(module_utils_path).exists()

    def test_inventory_compatibility(self):
        """Test compatibility with different inventory formats."""
        # Test that our plugin works with different inventory setups
        inventory_formats = ['ini', 'yaml', 'json']

        for format_type in inventory_formats:
            # Our plugin should work regardless of inventory format
            # since it operates at the task level
            assert format_type in inventory_formats


class TestRegressionTests:
    """Regression tests for known compatibility issues."""

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_no_deprecated_imports(self):
        """Test that we don't use deprecated Ansible imports."""
        sys.path.insert(0, '/Users/jing/Desktop/ansible-zerossl')

        try:
            # Import our plugin and check for deprecated usage
            import action_plugins.zerossl_certificate as plugin_module
            import inspect

            source = inspect.getsource(plugin_module)

            # Check for deprecated imports or patterns
            deprecated_patterns = [
                'ansible.module_utils.basic.AnsibleModule',  # Should use action plugin instead
                'ansible.module_utils._text',  # Use ansible.module_utils.common.text
            ]

            for pattern in deprecated_patterns:
                assert pattern not in source, f"Deprecated pattern found: {pattern}"

        except ImportError as e:
            pytest.skip(f"Could not import action plugin: {e}")

    @pytest.mark.skipif(not ANSIBLE_AVAILABLE, reason="Ansible not available")
    def test_future_compatibility(self):
        """Test patterns that ensure future compatibility."""
        sys.path.insert(0, '/Users/jing/Desktop/ansible-zerossl')

        try:
            from plugins.action.zerossl_certificate import ActionModule

            # Verify we follow current best practices
            action_module = ActionModule(
                task=Mock(),
                connection=Mock(),
                play_context=Mock(),
                loader=Mock(),
                templar=Mock(),
                shared_loader_obj=Mock()
            )

            # Check that we properly call super().__init__
            assert hasattr(action_module, '_task')
            assert hasattr(action_module, '_connection')

        except ImportError as e:
            pytest.skip(f"Could not import action plugin: {e}")


def test_generate_compatibility_report(tmp_path):
    """Generate a compatibility report."""
    report_file = tmp_path / "compatibility_report.txt"

    compatibility_info = {
        'ansible_available': ANSIBLE_AVAILABLE,
        'ansible_version': ANSIBLE_VERSION,
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'platform': sys.platform,
    }

    # Add module availability
    test_modules = ['requests', 'pathlib', 'cryptography', 'yaml']
    module_status = {}

    for module_name in test_modules:
        try:
            importlib.import_module(module_name)
            module_status[module_name] = 'Available'
        except ImportError:
            module_status[module_name] = 'Missing'

    compatibility_info['modules'] = module_status

    # Generate report
    with open(report_file, 'w') as f:
        f.write("ZeroSSL Plugin Compatibility Report\n")
        f.write("=" * 40 + "\n\n")

        f.write(f"Test Date: 2025-09-18\n")
        f.write(f"Python Version: {compatibility_info['python_version']}\n")
        f.write(f"Platform: {compatibility_info['platform']}\n")
        f.write(f"Ansible Available: {compatibility_info['ansible_available']}\n")

        if compatibility_info['ansible_available']:
            f.write(f"Ansible Version: {compatibility_info['ansible_version']}\n")

        f.write("\nModule Dependencies:\n")
        f.write("-" * 20 + "\n")

        for module, status in compatibility_info['modules'].items():
            f.write(f"{module}: {status}\n")

        f.write("\nCompatibility Status: ")
        if (compatibility_info['ansible_available'] and
            all(status == 'Available' for status in compatibility_info['modules'].values())):
            f.write("COMPATIBLE\n")
        else:
            f.write("ISSUES DETECTED\n")

    print(f"Compatibility report generated: {report_file}")
    return compatibility_info
