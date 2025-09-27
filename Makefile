# Makefile for Ansible ZeroSSL Plugin Development

.PHONY: help install test test-unit test-integration test-contract test-component test-slow lint format clean docs \
        coverage-automation quality-gates performance validate ci-simulation

# Default target
help:
	@echo "ZeroSSL Ansible Plugin Development Commands"
	@echo "=========================================="
	@echo ""
	@echo "Setup Commands:"
	@echo "  install          - Install development dependencies"
	@echo "  dev-setup        - Complete development environment setup"
	@echo ""
	@echo "Test Commands:"
	@echo "  test             - Run all tests"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-component   - Run component tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-contract    - Run contract tests only"
	@echo "  test-slow        - Run slow tests"
	@echo "  test-network     - Run network-dependent tests"
	@echo "  test-parallel    - Run tests in parallel"
	@echo ""
	@echo "Coverage Commands:"
	@echo "  coverage         - Run tests with coverage report"
	@echo "  coverage-automation - Run full coverage automation"
	@echo ""
	@echo "Quality Commands:"
	@echo "  quality-gates    - Run test quality gates"
	@echo "  performance      - Run performance validation"
	@echo "  lint             - Run code linting"
	@echo "  format           - Format code with black"
	@echo "  type-check       - Run type checking with mypy"
	@echo ""
	@echo "CI/CD Commands:"
	@echo "  validate         - Full validation (like CI)"
	@echo "  ci-simulation    - Simulate CI pipeline locally"
	@echo "  quick            - Quick development check"
	@echo ""
	@echo "Maintenance Commands:"
	@echo "  clean            - Clean build artifacts"
	@echo "  docs             - Build documentation"

# Installation
install:
	pip install -r requirements.txt
	pip install -e .[dev]

# Testing targets
test:
	pytest -v

test-unit:
	pytest tests/unit/ -v

test-component:
	pytest tests/component/ -v

test-integration:
	pytest -v -m integration

test-contract:
	pytest -v -m contract

test-slow:
	pytest -v -m slow

test-network:
	pytest -v -m network

test-parallel:
	pytest -v -n auto

# Code quality
lint:
	flake8 action_plugins/ module_utils/ tests/
	mypy action_plugins/ module_utils/

format:
	black action_plugins/ module_utils/ tests/

type-check:
	mypy action_plugins/ module_utils/

# Coverage
coverage:
	pytest --cov=plugins.action --cov=plugins.module_utils --cov-report=html --cov-report=xml --cov-report=term-missing --cov-fail-under=80 --cov-branch

coverage-xml:
	pytest --cov=plugins.action --cov=plugins.module_utils --cov-report=xml

coverage-automation:
	@echo "Running coverage automation..."
	python scripts/coverage_automation.py

# Quality Gates and Performance
quality-gates:
	@echo "Running test quality gates..."
	python scripts/test_quality_gates.py

performance:
	@echo "Running performance validation..."
	python scripts/performance_validation.py

# CI/CD Simulation
ci-simulation: quality-gates test-unit test-component coverage-automation
	@echo "✅ CI simulation complete!"

quick:
	@echo "Running quick development check..."
	pytest tests/unit/test_api_client.py tests/unit/test_certificate_manager.py -v

# Cleanup
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	rm -rf collections/
	rm -f coverage.xml coverage.json
	rm -f quality_gate_results.json
	rm -f performance_results.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Documentation
docs:
	sphinx-build -b html docs/ docs/_build/html/

docs-clean:
	rm -rf docs/_build/

# Development helpers
dev-setup: install
	pre-commit install

ansible-test:
	ansible-test sanity --python 3.12

ansible-test-integration:
	ansible-test integration --python 3.12

# Quick checks before commit
check: lint type-check test-unit

# Full validation
validate: clean quality-gates performance test-unit test-component coverage-automation
	@echo "✅ Full validation complete!"

# Release preparation
release-check: validate test docs
