# Integration Tests

This directory contains **real integration tests** that make actual API calls to ZeroSSL.

## Test Types

### `/tests/unit/` - Unit Tests
- Test individual components in isolation
- All external dependencies mocked
- Fast execution, no network calls
- Run with: `pytest tests/unit/`

### `/tests/component/` - Component Tests
- Test how multiple components work together
- External APIs mocked, internal integration tested
- Medium execution time
- Run with: `pytest tests/component/`

### `/tests/integration/` - Integration Tests ⚠️
- **REAL API CALLS** to ZeroSSL
- Test actual integration with external systems
- Require valid API keys and test domains
- Slow execution, may cost API quota
- Run with: `pytest tests/integration/`

## Running Integration Tests

### Prerequisites

1. **ZeroSSL API Key**: Set environment variable
   ```bash
   export ZEROSSL_API_KEY="your_actual_api_key_here"
   ```

2. **Test Domains**: Domains you control for validation
   ```bash
   export ZEROSSL_TEST_DOMAINS="test.yourdomain.com,api.yourdomain.com"
   ```

3. **Domain Control**: Ability to place files on your test domains for HTTP validation

### Running Tests

```bash
# Run all integration tests
pytest tests/integration/ -v

# Run only integration tests (skip if env not set)
pytest -m integration

# Run integration tests with verbose output
pytest tests/integration/ -v -s

# Skip integration tests (run everything else)
pytest -m "not integration"

# Run specific integration test
pytest tests/integration/test_live_certificate_lifecycle.py::TestLiveCertificateLifecycle::test_create_and_validate_certificate_http
```

### Environment Variables

| Variable                         | Required | Description                                |
|----------------------------------|----------|--------------------------------------------|
| `ZEROSSL_API_KEY`                | Yes      | Your ZeroSSL API key                       |
| `ZEROSSL_CERT_CSR_DIR`           | No       | Your custom csr dir                        |
| `ZEROSSL_TEST_DOMAINS`           | Yes      | Comma-separated domains you control        |
| `ZEROSSL_SKIP_MANUAL_VALIDATION` | No       | Skip manual validation steps (for CI)      |
| `ZEROSSL_CLEANUP_AFTER_TESTS`    | No       | Clean up test certificates (default: true) |

## Test Files

### `test_live_certificate_lifecycle.py`
- Full end-to-end certificate creation and validation
- Tests complete workflow with real domains
- Includes manual validation steps
- **Costs API quota** - use sparingly

### `test_live_api_contract.py`
- Validates ZeroSSL API contract compliance
- Tests API response formats and error handling
- Performance and concurrency testing
- Lower API quota impact

### `conftest_integration.py`
- Fixtures and configuration for live testing
- Environment validation
- Cleanup utilities

## CI/CD Considerations

Integration tests are **not suitable for regular CI** because they:
- Require real API keys and domain control
- Use API quota
- Take significant time
- May fail due to external factors

Consider running integration tests:
- Manually before releases
- In nightly builds with dedicated test infrastructure
- In staging environments with test domains

## Cost and Rate Limiting

ZeroSSL has rate limits and quotas:
- Free tier: 300 API requests/day
- Certificate creation counts toward quota
- Failed validations still consume quota

**Be conservative** with integration test runs to avoid hitting limits.

## Debugging

### Test Failures
- Check API key validity
- Verify domain control
- Check network connectivity
- Review ZeroSSL dashboard for certificate status

### Common Issues
- **Authentication errors**: Check `ZEROSSL_API_KEY`
- **Domain validation failures**: Ensure you can place files on test domains
- **Rate limit errors**: Wait or use different API key
- **Timeout errors**: Increase timeouts in test config

### Manual Cleanup
If tests fail and leave certificates, manually clean up via:
- ZeroSSL dashboard
- Certificate IDs are logged in test output

## Adding New Integration Tests

1. Add `@pytest.mark.integration` and `@pytest.mark.live` markers
2. Use fixtures from `conftest_integration.py`
3. Handle API errors gracefully
4. Add certificate IDs to cleanup list
5. Consider API quota impact
6. Test with real domains you control

## Security Notes

- Never commit API keys to version control
- Use separate API keys for testing
- Limit test domain exposure
- Review certificate cleanup procedures
