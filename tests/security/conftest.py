"""
Security test fixtures and utilities
"""
import pytest
import tempfile
import os
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.config.settings import Settings
from src.database.models import Base
from src.web.app import create_app


@pytest.fixture(scope="function")
def security_database():
    """Create a temporary database for security testing"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_file:
        db_path = temp_file.name
    
    # Create database URL
    db_url = f"sqlite:///{db_path}"
    
    # Initialize database
    engine = create_engine(db_url, echo=False)
    Base.metadata.create_all(engine)
    
    yield db_url
    
    # Cleanup
    engine.dispose()
    os.unlink(db_path)


@pytest.fixture(scope="function")
def security_settings(security_database):
    """Settings optimized for security testing"""
    # Override settings for security tests
    os.environ.update({
        'ARGUS_ENV': 'security_testing',
        'ARGUS_DATABASE_URL': security_database,
        'ARGUS_MOCK_MODE': 'true',
        'ARGUS_LOG_LEVEL': 'WARNING',
        'ARGUS_SECRET_KEY': 'test-secret-key-for-security-testing',
        'ARGUS_ENABLE_ALERTS': 'false',
        'ARGUS_RATE_LIMIT_ENABLED': 'true',
        'ARGUS_RATE_LIMIT_PER_MINUTE': '10'
    })
    
    settings = Settings()
    
    yield settings
    
    # Cleanup environment
    cleanup_vars = [
        'ARGUS_ENV', 'ARGUS_DATABASE_URL', 'ARGUS_MOCK_MODE',
        'ARGUS_LOG_LEVEL', 'ARGUS_SECRET_KEY', 'ARGUS_ENABLE_ALERTS',
        'ARGUS_RATE_LIMIT_ENABLED', 'ARGUS_RATE_LIMIT_PER_MINUTE'
    ]
    for var in cleanup_vars:
        os.environ.pop(var, None)


@pytest.fixture(scope="function")
def security_app(security_settings):
    """Flask app configured for security testing"""
    app = create_app(security_settings)
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
    
    with app.app_context():
        yield app


@pytest.fixture(scope="function")
def security_client(security_app):
    """Test client for security testing"""
    return security_app.test_client()


@pytest.fixture(scope="function")
def security_db_session(security_settings):
    """Database session for security testing"""
    engine = create_engine(security_settings.db_path)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    
    yield session
    
    session.close()


@pytest.fixture(scope="function")
def malicious_payloads():
    """Common malicious payloads for security testing"""
    return {
        'sql_injection': [
            "'; DROP TABLE devices; --",
            "' OR '1'='1",
            "1' UNION SELECT * FROM devices--",
            "'; INSERT INTO devices VALUES('hacked'); --",
            "admin'--",
            "' OR 1=1#"
        ],
        'xss': [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'><script>alert(String.fromCharCode(88,83,83))</script>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<%2Fscript%3E%3Cscript%3Ealert('XSS')%3C%2Fscript%3E"
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ],
        'command_injection': [
            "; cat /etc/passwd",
            "& whoami",
            "| ls -la",
            "`id`",
            "$(cat /etc/passwd)",
            "; rm -rf /",
            "&& netstat -an"
        ],
        'ldap_injection': [
            "*)(uid=*))(|(uid=*",
            "*)(|(mail=*))",
            "*)(|(objectClass=*))",
            "admin)(&(objectClass=*",
            "*))(|(cn=*))"
        ],
        'xml_injection': [
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            "<!--#exec cmd='/bin/cat /etc/passwd'-->",
            "<![CDATA[malicious content]]>"
        ]
    }


@pytest.fixture(scope="function")
def invalid_inputs():
    """Various invalid input types for validation testing"""
    return {
        'long_strings': 'A' * 10000,
        'unicode_attacks': '\u0000\u0001\u0002\u0003\u0004\u0005',
        'format_strings': '%s%s%s%s%s%s',
        'null_bytes': 'test\x00.txt',
        'control_chars': '\x08\x09\x0a\x0b\x0c\x0d',
        'empty_values': ['', None, [], {}],
        'oversized_numbers': 99999999999999999999999999999999,
        'negative_numbers': -999999999,
        'special_floats': [float('inf'), float('-inf'), float('nan')],
        'malformed_json': '{"unclosed": "json"',
        'malformed_xml': '<unclosed><tag>',
        'binary_data': b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
    }