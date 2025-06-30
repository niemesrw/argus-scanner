# Security Tests

This directory contains comprehensive security tests for the Argus Scanner application.

## Test Categories

### Input Validation Tests (`test_input_validation.py`)
- API endpoint input validation
- Parameter length validation 
- Data type validation
- Required fields validation
- IP and MAC address format validation
- JSON payload validation
- Unicode and encoding validation
- Content type validation
- HTTP method validation

**11 test methods covering comprehensive input validation**

### SQL Injection Prevention Tests (`test_sql_injection.py`)
- Device search SQL injection protection
- Filter parameter injection protection
- Vulnerability search injection protection
- Alert filter injection protection
- Raw SQL injection protection
- ORM-level injection protection
- Parameterized query validation
- Time-based injection protection
- Union-based injection protection
- Blind injection protection

**10 test methods covering all major SQL injection attack vectors**

### XSS Prevention Tests (`test_xss_prevention.py`)
- Device list XSS prevention
- Device detail XSS prevention
- Vulnerability list XSS prevention
- Alert list XSS prevention
- API response XSS prevention
- Search results XSS prevention
- Error message XSS prevention
- Content Security Policy headers
- Script tag injection prevention
- Event handler injection prevention
- URL-based XSS prevention
- JSON XSS prevention

**12 test methods covering all major XSS attack vectors**

### Authentication and Rate Limiting Tests (`test_authentication_and_rate_limiting.py`)
- Admin endpoint access control
- API endpoint authentication
- Session management security
- CSRF protection
- Brute force protection
- Password policy enforcement
- Privilege escalation prevention
- JWT token security
- API key security
- CORS security
- HTTP security headers
- Information disclosure prevention
- API rate limiting
- Concurrent request handling
- Large payload protection
- Slow request timeout
- Resource exhaustion protection

**17 test methods across 2 test classes covering authentication and rate limiting**

## Test Configuration

Security tests use the `@pytest.mark.security` marker and include:

- Isolated test database
- Mock application environment
- Comprehensive malicious payload collections
- Invalid input generators
- Security-focused fixtures

## Running Security Tests

```bash
# Run all security tests
pytest tests/security/ -v

# Run specific test category
pytest tests/security/test_input_validation.py -v
pytest tests/security/test_sql_injection.py -v
pytest tests/security/test_xss_prevention.py -v
pytest tests/security/test_authentication_and_rate_limiting.py -v

# Run with coverage
pytest tests/security/ -v --cov=src --cov-report=html
```

## Integration with CI/CD

- **Fast CI Pipeline**: Security tests run in the main CI pipeline (excluding slow tests)
- **Nightly/Manual**: Complete security test suite runs in the E2E workflow
- **Coverage**: Security tests contribute to overall test coverage metrics

## Security Test Fixtures

The `conftest.py` provides:
- `security_database`: Isolated test database
- `security_settings`: Security-optimized settings
- `security_app`: Test Flask application
- `security_client`: Test HTTP client
- `malicious_payloads`: Common attack payloads
- `invalid_inputs`: Various invalid input types

## Best Practices

1. **Comprehensive Coverage**: Tests cover all major web application security risks
2. **Realistic Payloads**: Uses actual attack vectors and malicious inputs
3. **Isolated Environment**: Each test runs in isolation with clean state
4. **Performance Aware**: Marked appropriately for CI/CD pipeline optimization
5. **Documentation**: Clear test names and comprehensive assertions

## Security Testing Philosophy

These tests follow a **defense-in-depth** approach:
- **Input validation** at the application boundary
- **SQL injection protection** at the database layer
- **XSS prevention** at the presentation layer
- **Authentication/authorization** at the access control layer
- **Rate limiting** at the infrastructure layer

Total: **50+ individual security test methods** providing comprehensive security validation.