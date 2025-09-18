# Makefile for Ansible ZeroSSL Plugin Development

.PHONY: help install test test-unit test-integration test-contract test-slow lint format clean docs

# Default target
help:
	@echo "Available targets:"
	@echo "  install          - Install development dependencies"
	@echo "  test            - Run all tests"
	@echo "  test-unit       - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-contract   - Run contract tests only"
	@echo "  test-slow       - Run slow tests"
	@echo "  test-network    - Run network-dependent tests"
	@echo "  lint            - Run code linting"
	@echo "  format          - Format code with black"
	@echo "  type-check      - Run type checking with mypy"
	@echo "  coverage        - Run tests with coverage report"
	@echo "  clean           - Clean build artifacts"
	@echo "  docs            - Build documentation"

# Installation
install:
	pip install -r requirements.txt
	pip install -e .[dev]

# Testing targets
test:
	pytest -v

test-unit:
	pytest -v -m unit

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
	pytest --cov=module_utils --cov=action_plugins --cov-report=html --cov-report=term-missing

coverage-xml:
	pytest --cov=module_utils --cov=action_plugins --cov-report=xml

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
	find . -type d -name __pycache__ -exec rm -rf {} +
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
validate: clean install lint type-check coverage

# Release preparation
release-check: validate test docs
