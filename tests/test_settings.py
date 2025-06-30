"""
Tests for configuration settings module
"""
import pytest
import os
from pathlib import Path
from unittest.mock import patch

from src.config.settings import Settings


class TestSettingsInitialization:
    """Test suite for Settings class initialization"""
    
    def test_default_initialization(self):
        """Test Settings initialization with default values"""
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings()
            
            # Environment defaults
            assert settings.environment == "production"
            assert settings.mock_mode is False
            
            # Database defaults
            assert settings.db_path == Path("/app/data/argus.db")
            
            # Logging defaults
            assert settings.log_level == "INFO"
            assert settings.log_path == Path("/app/logs")
            
            # Web server defaults
            assert settings.web_port == 8080
            assert settings.secret_key == "change-me-in-production"
            
            # Scanning defaults
            assert settings.network_range == "192.168.1.0/24"
            assert settings.scan_interval == 3600
            assert settings.scan_timeout == 300
            assert settings.max_parallel_scans == 5
            
            # Vulnerability detection defaults
            assert settings.cve_api_key is None
            assert settings.vulnerability_db_update_interval == 86400
            
            # Alerting defaults
            assert settings.alert_email_enabled is False
            assert settings.alert_email_smtp_host is None
            assert settings.alert_email_smtp_port == 587
            assert settings.alert_email_username is None
            assert settings.alert_email_password is None
            assert settings.alert_email_from is None
            assert settings.alert_email_to == []
            assert settings.alert_slack_enabled is False
            assert settings.alert_slack_webhook is None
            
            # Security defaults
            assert settings.enable_exploit_testing is False
            assert settings.authorized_networks == []
    
    def test_environment_variable_parsing(self):
        """Test Settings initialization with environment variables"""
        env_vars = {
            'ARGUS_ENV': 'development',
            'ARGUS_MOCK_MODE': 'true',
            'ARGUS_DB_PATH': '/custom/path/db.sqlite',
            'ARGUS_LOG_LEVEL': 'DEBUG',
            'ARGUS_LOG_PATH': '/custom/logs',
            'ARGUS_WEB_PORT': '9090',
            'ARGUS_SECRET_KEY': 'super-secret-key',
            'ARGUS_NETWORK_RANGE': '10.0.0.0/16',
            'ARGUS_SCAN_INTERVAL': '1800',
            'ARGUS_SCAN_TIMEOUT': '600',
            'ARGUS_MAX_PARALLEL_SCANS': '10',
            'ARGUS_CVE_API_KEY': 'api-key-123',
            'ARGUS_VULN_DB_UPDATE_INTERVAL': '43200',
            'ARGUS_ALERT_EMAIL_ENABLED': 'true',
            'ARGUS_SMTP_HOST': 'smtp.example.com',
            'ARGUS_SMTP_PORT': '465',
            'ARGUS_SMTP_USERNAME': 'alerts@example.com',
            'ARGUS_SMTP_PASSWORD': 'password123',
            'ARGUS_ALERT_FROM': 'alerts@example.com',
            'ARGUS_ALERT_TO': 'admin@example.com,security@example.com',
            'ARGUS_ALERT_SLACK_ENABLED': 'true',
            'ARGUS_SLACK_WEBHOOK': 'https://hooks.slack.com/services/XXX',
            'ARGUS_ENABLE_EXPLOIT_TESTING': 'true',
            'ARGUS_AUTHORIZED_NETWORKS': '192.168.1.0/24,10.0.0.0/8'
        }
        
        with patch.dict(os.environ, env_vars, clear=True):
            settings = Settings()
            
            # Environment variables
            assert settings.environment == 'development'
            assert settings.mock_mode is True
            assert settings.db_path == Path('/custom/path/db.sqlite')
            assert settings.log_level == 'DEBUG'
            assert settings.log_path == Path('/custom/logs')
            assert settings.web_port == 9090
            assert settings.secret_key == 'super-secret-key'
            assert settings.network_range == '10.0.0.0/16'
            assert settings.scan_interval == 1800
            assert settings.scan_timeout == 600
            assert settings.max_parallel_scans == 10
            assert settings.cve_api_key == 'api-key-123'
            assert settings.vulnerability_db_update_interval == 43200
            assert settings.alert_email_enabled is True
            assert settings.alert_email_smtp_host == 'smtp.example.com'
            assert settings.alert_email_smtp_port == 465
            assert settings.alert_email_username == 'alerts@example.com'
            assert settings.alert_email_password == 'password123'
            assert settings.alert_email_from == 'alerts@example.com'
            assert settings.alert_email_to == ['admin@example.com', 'security@example.com']
            assert settings.alert_slack_enabled is True
            assert settings.alert_slack_webhook == 'https://hooks.slack.com/services/XXX'
            assert settings.enable_exploit_testing is True
            assert settings.authorized_networks == ['192.168.1.0/24', '10.0.0.0/8']


class TestBooleanParsing:
    """Test suite for boolean environment variable parsing"""
    
    @pytest.mark.parametrize("value,expected", [
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("", False),
        ("invalid", False),
        ("1", False),  # Should only accept "true" case-insensitively
        ("0", False),
    ])
    def test_mock_mode_parsing(self, value, expected):
        """Test mock mode boolean parsing"""
        with patch.dict(os.environ, {'ARGUS_MOCK_MODE': value}, clear=True):
            settings = Settings()
            assert settings.mock_mode is expected
    
    @pytest.mark.parametrize("value,expected", [
        ("true", True),
        ("TRUE", True),
        ("false", False),
        ("", False),
    ])
    def test_alert_email_enabled_parsing(self, value, expected):
        """Test alert email enabled boolean parsing"""
        with patch.dict(os.environ, {'ARGUS_ALERT_EMAIL_ENABLED': value}, clear=True):
            settings = Settings()
            assert settings.alert_email_enabled is expected
    
    @pytest.mark.parametrize("value,expected", [
        ("true", True),
        ("false", False),
        ("", False),
    ])
    def test_alert_slack_enabled_parsing(self, value, expected):
        """Test alert slack enabled boolean parsing"""
        with patch.dict(os.environ, {'ARGUS_ALERT_SLACK_ENABLED': value}, clear=True):
            settings = Settings()
            assert settings.alert_slack_enabled is expected
    
    @pytest.mark.parametrize("value,expected", [
        ("true", True),
        ("false", False),
        ("", False),
    ])
    def test_enable_exploit_testing_parsing(self, value, expected):
        """Test exploit testing enabled boolean parsing"""
        with patch.dict(os.environ, {'ARGUS_ENABLE_EXPLOIT_TESTING': value}, clear=True):
            settings = Settings()
            assert settings.enable_exploit_testing is expected


class TestIntegerParsing:
    """Test suite for integer environment variable parsing"""
    
    def test_web_port_parsing(self):
        """Test web port integer parsing"""
        with patch.dict(os.environ, {'ARGUS_WEB_PORT': '3000'}, clear=True):
            settings = Settings()
            assert settings.web_port == 3000
            assert isinstance(settings.web_port, int)
    
    def test_scan_interval_parsing(self):
        """Test scan interval integer parsing"""
        with patch.dict(os.environ, {'ARGUS_SCAN_INTERVAL': '7200'}, clear=True):
            settings = Settings()
            assert settings.scan_interval == 7200
            assert isinstance(settings.scan_interval, int)
    
    def test_scan_timeout_parsing(self):
        """Test scan timeout integer parsing"""
        with patch.dict(os.environ, {'ARGUS_SCAN_TIMEOUT': '120'}, clear=True):
            settings = Settings()
            assert settings.scan_timeout == 120
            assert isinstance(settings.scan_timeout, int)
    
    def test_max_parallel_scans_parsing(self):
        """Test max parallel scans integer parsing"""
        with patch.dict(os.environ, {'ARGUS_MAX_PARALLEL_SCANS': '15'}, clear=True):
            settings = Settings()
            assert settings.max_parallel_scans == 15
            assert isinstance(settings.max_parallel_scans, int)
    
    def test_smtp_port_parsing(self):
        """Test SMTP port integer parsing"""
        with patch.dict(os.environ, {'ARGUS_SMTP_PORT': '25'}, clear=True):
            settings = Settings()
            assert settings.alert_email_smtp_port == 25
            assert isinstance(settings.alert_email_smtp_port, int)
    
    def test_vulnerability_db_update_interval_parsing(self):
        """Test vulnerability DB update interval integer parsing"""
        with patch.dict(os.environ, {'ARGUS_VULN_DB_UPDATE_INTERVAL': '21600'}, clear=True):
            settings = Settings()
            assert settings.vulnerability_db_update_interval == 21600
            assert isinstance(settings.vulnerability_db_update_interval, int)


class TestListParsing:
    """Test suite for comma-separated list parsing"""
    
    def test_alert_email_to_parsing(self):
        """Test alert email recipients list parsing"""
        with patch.dict(os.environ, {'ARGUS_ALERT_TO': 'user1@example.com,user2@example.com,user3@example.com'}, clear=True):
            settings = Settings()
            expected = ['user1@example.com', 'user2@example.com', 'user3@example.com']
            assert settings.alert_email_to == expected
    
    def test_alert_email_to_empty(self):
        """Test alert email recipients with empty value"""
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings()
            assert settings.alert_email_to == []
    
    def test_alert_email_to_single_value(self):
        """Test alert email recipients with single value"""
        with patch.dict(os.environ, {'ARGUS_ALERT_TO': 'admin@example.com'}, clear=True):
            settings = Settings()
            assert settings.alert_email_to == ['admin@example.com']
    
    def test_authorized_networks_parsing(self):
        """Test authorized networks list parsing"""
        with patch.dict(os.environ, {'ARGUS_AUTHORIZED_NETWORKS': '192.168.1.0/24,10.0.0.0/8,172.16.0.0/12'}, clear=True):
            settings = Settings()
            expected = ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12']
            assert settings.authorized_networks == expected
    
    def test_authorized_networks_empty(self):
        """Test authorized networks with empty value"""
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings()
            assert settings.authorized_networks == []
    
    def test_authorized_networks_with_spaces(self):
        """Test authorized networks parsing with spaces"""
        with patch.dict(os.environ, {'ARGUS_AUTHORIZED_NETWORKS': '192.168.1.0/24, 10.0.0.0/8 ,172.16.0.0/12'}, clear=True):
            settings = Settings()
            # Should preserve spaces as they might be significant
            expected = ['192.168.1.0/24', ' 10.0.0.0/8 ', '172.16.0.0/12']
            assert settings.authorized_networks == expected


class TestPathParsing:
    """Test suite for Path object parsing"""
    
    def test_db_path_parsing(self):
        """Test database path parsing"""
        with patch.dict(os.environ, {'ARGUS_DB_PATH': '/custom/database/path.db'}, clear=True):
            settings = Settings()
            assert settings.db_path == Path('/custom/database/path.db')
            assert isinstance(settings.db_path, Path)
    
    def test_log_path_parsing(self):
        """Test log path parsing"""
        with patch.dict(os.environ, {'ARGUS_LOG_PATH': '/var/log/argus'}, clear=True):
            settings = Settings()
            assert settings.log_path == Path('/var/log/argus')
            assert isinstance(settings.log_path, Path)


class TestEnvironmentProperties:
    """Test suite for environment-related properties"""
    
    def test_is_development_true(self):
        """Test is_development property when environment is development"""
        with patch.dict(os.environ, {'ARGUS_ENV': 'development'}, clear=True):
            settings = Settings()
            assert settings.is_development is True
            assert settings.is_production is False
    
    def test_is_production_true(self):
        """Test is_production property when environment is production"""
        with patch.dict(os.environ, {'ARGUS_ENV': 'production'}, clear=True):
            settings = Settings()
            assert settings.is_production is True
            assert settings.is_development is False
    
    def test_is_production_default(self):
        """Test is_production property with default environment"""
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings()
            assert settings.is_production is True
            assert settings.is_development is False
    
    def test_environment_staging(self):
        """Test environment properties with staging environment"""
        with patch.dict(os.environ, {'ARGUS_ENV': 'staging'}, clear=True):
            settings = Settings()
            assert settings.environment == 'staging'
            assert settings.is_development is False
            assert settings.is_production is False


class TestConfigurationValidation:
    """Test suite for configuration validation scenarios"""
    
    def test_development_configuration(self):
        """Test typical development configuration"""
        dev_env = {
            'ARGUS_ENV': 'development',
            'ARGUS_MOCK_MODE': 'true',
            'ARGUS_LOG_LEVEL': 'DEBUG',
            'ARGUS_WEB_PORT': '8080',
            'ARGUS_SCAN_INTERVAL': '300',
            'ARGUS_ENABLE_EXPLOIT_TESTING': 'false'
        }
        
        with patch.dict(os.environ, dev_env, clear=True):
            settings = Settings()
            
            assert settings.is_development
            assert settings.mock_mode
            assert settings.log_level == 'DEBUG'
            assert settings.web_port == 8080
            assert settings.scan_interval == 300
            assert settings.enable_exploit_testing is False
    
    def test_production_configuration(self):
        """Test typical production configuration"""
        prod_env = {
            'ARGUS_ENV': 'production',
            'ARGUS_MOCK_MODE': 'false',
            'ARGUS_LOG_LEVEL': 'INFO',
            'ARGUS_SECRET_KEY': 'secure-production-key',
            'ARGUS_DB_PATH': '/var/lib/argus/argus.db',
            'ARGUS_LOG_PATH': '/var/log/argus',
            'ARGUS_ALERT_EMAIL_ENABLED': 'true',
            'ARGUS_SMTP_HOST': 'mail.company.com',
            'ARGUS_ALERT_FROM': 'argus@company.com',
            'ARGUS_ALERT_TO': 'security@company.com,ops@company.com',
            'ARGUS_ENABLE_EXPLOIT_TESTING': 'false',
            'ARGUS_AUTHORIZED_NETWORKS': '10.0.0.0/8,192.168.0.0/16'
        }
        
        with patch.dict(os.environ, prod_env, clear=True):
            settings = Settings()
            
            assert settings.is_production
            assert settings.mock_mode is False
            assert settings.log_level == 'INFO'
            assert settings.secret_key == 'secure-production-key'
            assert settings.db_path == Path('/var/lib/argus/argus.db')
            assert settings.log_path == Path('/var/log/argus')
            assert settings.alert_email_enabled is True
            assert settings.alert_email_smtp_host == 'mail.company.com'
            assert settings.alert_email_from == 'argus@company.com'
            assert len(settings.alert_email_to) == 2
            assert settings.enable_exploit_testing is False
            assert len(settings.authorized_networks) == 2
    
    def test_security_focused_configuration(self):
        """Test security-focused configuration validation"""
        with patch.dict(os.environ, {'ARGUS_ENABLE_EXPLOIT_TESTING': 'true'}, clear=True):
            settings = Settings()
            # This should only be enabled in controlled environments
            assert settings.enable_exploit_testing is True
    
    def test_minimal_configuration(self):
        """Test minimal configuration with only essential settings"""
        minimal_env = {
            'ARGUS_ENV': 'development',
            'ARGUS_NETWORK_RANGE': '192.168.1.0/24'
        }
        
        with patch.dict(os.environ, minimal_env, clear=True):
            settings = Settings()
            
            assert settings.environment == 'development'
            assert settings.network_range == '192.168.1.0/24'
            # All other settings should use defaults
            assert settings.scan_interval == 3600
            assert settings.web_port == 8080


class TestEdgeCases:
    """Test suite for edge cases and error conditions"""
    
    def test_empty_string_environment_variables(self):
        """Test handling of empty string environment variables"""
        empty_env = {
            'ARGUS_NETWORK_RANGE': '',
            'ARGUS_SECRET_KEY': '',
            'ARGUS_LOG_LEVEL': ''
        }
        
        with patch.dict(os.environ, empty_env, clear=True):
            settings = Settings()
            
            # Empty strings should be treated as provided values
            assert settings.network_range == ''
            assert settings.secret_key == ''
            assert settings.log_level == ''
    
    def test_none_values_for_optional_settings(self):
        """Test that optional settings can be None"""
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings()
            
            assert settings.cve_api_key is None
            assert settings.alert_email_smtp_host is None
            assert settings.alert_email_username is None
            assert settings.alert_email_password is None
            assert settings.alert_email_from is None
            assert settings.alert_slack_webhook is None
    
    def test_case_sensitivity_for_booleans(self):
        """Test case sensitivity in boolean parsing"""
        test_cases = [
            ('True', True),
            ('true', True),
            ('TRUE', True),
            ('tRuE', True),
            ('False', False),
            ('false', False),
            ('FALSE', False),
            ('anything_else', False)
        ]
        
        for value, expected in test_cases:
            with patch.dict(os.environ, {'ARGUS_MOCK_MODE': value}, clear=True):
                settings = Settings()
                assert settings.mock_mode is expected
    
    def test_integer_parsing_edge_cases(self):
        """Test integer parsing with various inputs"""
        # Valid integer
        with patch.dict(os.environ, {'ARGUS_WEB_PORT': '8080'}, clear=True):
            settings = Settings()
            assert settings.web_port == 8080
        
        # Zero
        with patch.dict(os.environ, {'ARGUS_SCAN_INTERVAL': '0'}, clear=True):
            settings = Settings()
            assert settings.scan_interval == 0
        
        # Large number
        with patch.dict(os.environ, {'ARGUS_VULN_DB_UPDATE_INTERVAL': '999999'}, clear=True):
            settings = Settings()
            assert settings.vulnerability_db_update_interval == 999999


class TestSettingsImmutability:
    """Test suite for settings immutability and state"""
    
    def test_settings_state_consistency(self):
        """Test that settings maintain consistent state"""
        with patch.dict(os.environ, {'ARGUS_ENV': 'development'}, clear=True):
            settings = Settings()
            
            # Properties should be consistent
            if settings.is_development:
                assert not settings.is_production
                assert settings.environment == 'development'
    
    def test_multiple_instances_independence(self):
        """Test that multiple Settings instances are independent"""
        with patch.dict(os.environ, {'ARGUS_ENV': 'development'}, clear=True):
            settings1 = Settings()
        
        with patch.dict(os.environ, {'ARGUS_ENV': 'production'}, clear=True):
            settings2 = Settings()
        
        # Instances should reflect their respective environments
        assert settings1.environment == 'development'
        assert settings2.environment == 'production'
        assert settings1.is_development
        assert settings2.is_production