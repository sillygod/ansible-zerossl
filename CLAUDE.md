# Ansible ZeroSSL Certificate Management Plugin

## Project Context
Refactor and enhance the existing Ansible ZeroSSL certificate management plugin to meet modern Ansible standards and provide comprehensive SSL certificate automation.

## Technology Stack
- **Language**: Python 3.12
- **Framework**: Ansible Action Plugin
- **API**: ZeroSSL REST API
- **Testing**: pytest with Ansible test utilities
- **Security**: Ansible Vault for API key management

## Current Architecture
The project contains an existing action plugin at `action_plugins/zerossl_certificate.py` that provides basic certificate management functionality. This needs to be refactored to meet modern Ansible standards.

## Key Features
- Certificate lifecycle management (create, validate, download, renew)
- HTTP-01 and DNS-01 domain validation
- Multi-domain (SAN) certificate support
- Automatic renewal based on expiration thresholds
- Idempotent operations
- Comprehensive error handling and retry logic

## Project Structure
```
action_plugins/
├── __init__.py
└── zerossl_certificate.py        # Main plugin implementation

tests/
├── unit/                         # Unit tests for components
├── integration/                  # Full workflow tests
└── fixtures/                     # Test data and mocks

specs/001-develop-an-ansible/     # Design documentation
├── spec.md                       # Feature specification
├── plan.md                       # Implementation plan
├── research.md                   # Technical research
├── data-model.md                # Data structures
├── quickstart.md                # Usage guide
└── contracts/                    # API contracts
```

## Development Guidelines
- Follow Ansible plugin development standards
- Implement TDD with comprehensive test coverage
- Use type hints and modern Python features
- Handle ZeroSSL API rate limits gracefully
- Ensure operations are idempotent
- Provide clear error messages and documentation

## Recent Changes
- 002-the-original-test: Added Python 3.12+ + ansible>=8.0.0, requests>=2.31.0, cryptography>=41.0.0
- Created comprehensive feature specification and implementation plan
- Researched Ansible plugin standards and ZeroSSL API capabilities

<!-- AUTO-GENERATED CONTEXT - DO NOT EDIT BELOW THIS LINE -->
<!-- END AUTO-GENERATED CONTEXT -->
