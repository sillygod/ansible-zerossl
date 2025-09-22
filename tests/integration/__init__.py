# -*- coding: utf-8 -*-
"""
Real integration tests for Ansible ZeroSSL plugin.

These tests make actual API calls to ZeroSSL and require:
- Valid ZeroSSL API key
- Test domains you control for validation
- Network connectivity

Run with: pytest -m integration
Skip with: pytest -m "not integration"
"""
