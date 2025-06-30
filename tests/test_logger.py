"""
Tests for logging configuration module
"""
import pytest
import logging
import sys
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, call
from io import StringIO

from src.utils.logger import setup_logging


class TestLoggingSetup:
    """Test suite for logging setup functionality"""
    
    def setup_method(self):
        """Setup for each test method"""
        # Clear existing handlers before each test
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def teardown_method(self):
        """Cleanup after each test method"""
        # Clear handlers after each test
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def test_log_directory_creation(self):
        """Test that log directory is created if it doesn't exist"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "logs" / "subdir"
            assert not log_path.exists()
            
            setup_logging("INFO", log_path)
            
            assert log_path.exists()
            assert log_path.is_dir()
    
    def test_log_directory_already_exists(self):
        """Test setup when log directory already exists"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "existing_logs"
            log_path.mkdir(parents=True, exist_ok=True)
            
            # Should not raise exception
            setup_logging("INFO", log_path)
            
            assert log_path.exists()
            assert log_path.is_dir()
    
    def test_root_logger_level_configuration(self):
        """Test root logger level is set correctly"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            # Test different log levels
            test_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
            
            for level in test_levels:
                setup_logging(level, log_path)
                root_logger = logging.getLogger()
                expected_level = getattr(logging, level.upper())
                assert root_logger.level == expected_level
    
    def test_case_insensitive_log_level(self):
        """Test that log level is case insensitive"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            test_cases = [
                ("debug", logging.DEBUG),
                ("Debug", logging.DEBUG),
                ("DEBUG", logging.DEBUG),
                ("info", logging.INFO),
                ("INFO", logging.INFO),
                ("warning", logging.WARNING),
                ("WARNING", logging.WARNING)
            ]
            
            for level_str, expected_level in test_cases:
                setup_logging(level_str, log_path)
                root_logger = logging.getLogger()
                assert root_logger.level == expected_level
    
    def test_existing_handlers_removal(self):
        """Test that existing handlers are removed before setup"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            # Add some existing handlers
            root_logger = logging.getLogger()
            existing_handler1 = logging.StreamHandler()
            existing_handler2 = logging.FileHandler(log_path / "old.log")
            root_logger.addHandler(existing_handler1)
            root_logger.addHandler(existing_handler2)
            
            initial_handler_count = len(root_logger.handlers)
            assert initial_handler_count == 2
            
            setup_logging("INFO", log_path)
            
            # Should have exactly 2 new handlers (console + file)
            assert len(root_logger.handlers) == 2
            # Old handlers should be removed
            assert existing_handler1 not in root_logger.handlers
            assert existing_handler2 not in root_logger.handlers


class TestConsoleHandler:
    """Test suite for console handler configuration"""
    
    def setup_method(self):
        """Setup for each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def teardown_method(self):
        """Cleanup after each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def test_console_handler_creation(self):
        """Test that console handler is created and added"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("INFO", log_path)
            
            root_logger = logging.getLogger()
            console_handlers = [h for h in root_logger.handlers if isinstance(h, logging.StreamHandler)]
            
            assert len(console_handlers) >= 1
            console_handler = console_handlers[0]
            assert console_handler.stream == sys.stdout
    
    def test_console_handler_format(self):
        """Test console handler formatting"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("INFO", log_path)
            
            root_logger = logging.getLogger()
            console_handlers = [h for h in root_logger.handlers 
                              if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)]
            
            assert len(console_handlers) >= 1
            console_handler = console_handlers[0]
            
            # Test the format string
            formatter = console_handler.formatter
            assert formatter is not None
            assert "%(asctime)s" in formatter._fmt
            assert "%(name)s" in formatter._fmt
            assert "%(levelname)s" in formatter._fmt
            assert "%(message)s" in formatter._fmt
    
    @patch('sys.stdout', new_callable=StringIO)
    def test_console_output(self, mock_stdout):
        """Test that console handler outputs to stdout"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("INFO", log_path)
            
            logger = logging.getLogger("test_logger")
            logger.info("Test console message")
            
            output = mock_stdout.getvalue()
            assert "Test console message" in output
            assert "test_logger" in output
            assert "INFO" in output


class TestFileHandler:
    """Test suite for file handler configuration"""
    
    def setup_method(self):
        """Setup for each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def teardown_method(self):
        """Cleanup after each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def test_file_handler_creation(self):
        """Test that file handler is created and added"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("INFO", log_path)
            
            root_logger = logging.getLogger()
            file_handlers = [h for h in root_logger.handlers if isinstance(h, logging.FileHandler)]
            
            assert len(file_handlers) >= 1
            file_handler = file_handlers[0]
            expected_log_file = log_path / "argus.log"
            assert Path(file_handler.baseFilename) == expected_log_file
    
    def test_file_handler_json_format(self):
        """Test that file handler uses JSON formatting"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("INFO", log_path)
            
            root_logger = logging.getLogger()
            file_handlers = [h for h in root_logger.handlers if isinstance(h, logging.FileHandler)]
            
            assert len(file_handlers) >= 1
            file_handler = file_handlers[0]
            
            # Check that formatter is JsonFormatter
            from pythonjsonlogger import jsonlogger
            assert isinstance(file_handler.formatter, jsonlogger.JsonFormatter)
    
    def test_file_logging_output(self):
        """Test that file handler writes JSON logs to file"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("INFO", log_path)
            
            logger = logging.getLogger("test_file_logger")
            logger.info("Test file message", extra={"custom_field": "test_value"})
            
            # Force flush handlers
            for handler in logging.getLogger().handlers:
                handler.flush()
            
            log_file = log_path / "argus.log"
            assert log_file.exists()
            
            # Read and verify JSON content
            with open(log_file, 'r') as f:
                log_content = f.read().strip()
            
            # Should be valid JSON
            log_entry = json.loads(log_content)
            assert log_entry["message"] == "Test file message"
            assert log_entry["name"] == "test_file_logger"
            assert log_entry["levelname"] == "INFO"
            assert log_entry["custom_field"] == "test_value"
    
    def test_log_file_path(self):
        """Test that log file is created in correct location"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "custom_logs"
            
            setup_logging("INFO", log_path)
            
            # Write a log message to ensure file creation
            logger = logging.getLogger("test")
            logger.info("Test message")
            
            # Force flush
            for handler in logging.getLogger().handlers:
                handler.flush()
            
            expected_file = log_path / "argus.log"
            assert expected_file.exists()


class TestThirdPartyLoggerConfiguration:
    """Test suite for third-party logger configuration"""
    
    def setup_method(self):
        """Setup for each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def teardown_method(self):
        """Cleanup after each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def test_third_party_loggers_level(self):
        """Test that third-party loggers are set to WARNING level"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("DEBUG", log_path)
            
            # Check that third-party loggers are set to WARNING
            third_party_loggers = ["urllib3", "requests", "werkzeug", "watchdog"]
            
            for logger_name in third_party_loggers:
                logger = logging.getLogger(logger_name)
                assert logger.level == logging.WARNING
    
    def test_third_party_loggers_suppression(self):
        """Test that third-party loggers don't spam with DEBUG messages"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("DEBUG", log_path)
            
            # Third-party loggers should not log DEBUG messages
            urllib3_logger = logging.getLogger("urllib3")
            requests_logger = logging.getLogger("requests")
            werkzeug_logger = logging.getLogger("werkzeug")
            watchdog_logger = logging.getLogger("watchdog")
            
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                urllib3_logger.debug("This should not appear")
                requests_logger.debug("This should not appear")
                werkzeug_logger.debug("This should not appear")
                watchdog_logger.debug("This should not appear")
                
                # But WARNING messages should appear
                urllib3_logger.warning("This should appear")
                
                output = mock_stdout.getvalue()
                assert "This should not appear" not in output
                assert "This should appear" in output


class TestLogLevelBehavior:
    """Test suite for log level behavior"""
    
    def setup_method(self):
        """Setup for each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def teardown_method(self):
        """Cleanup after each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def test_debug_level_logging(self):
        """Test DEBUG level logging behavior"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("DEBUG", log_path)
            
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                logger = logging.getLogger("test")
                logger.debug("Debug message")
                logger.info("Info message")
                logger.warning("Warning message")
                logger.error("Error message")
                logger.critical("Critical message")
                
                output = mock_stdout.getvalue()
                assert "Debug message" in output
                assert "Info message" in output
                assert "Warning message" in output
                assert "Error message" in output
                assert "Critical message" in output
    
    def test_info_level_logging(self):
        """Test INFO level logging behavior"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("INFO", log_path)
            
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                logger = logging.getLogger("test")
                logger.debug("Debug message")
                logger.info("Info message")
                logger.warning("Warning message")
                logger.error("Error message")
                
                output = mock_stdout.getvalue()
                assert "Debug message" not in output
                assert "Info message" in output
                assert "Warning message" in output
                assert "Error message" in output
    
    def test_warning_level_logging(self):
        """Test WARNING level logging behavior"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("WARNING", log_path)
            
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                logger = logging.getLogger("test")
                logger.debug("Debug message")
                logger.info("Info message")
                logger.warning("Warning message")
                logger.error("Error message")
                
                output = mock_stdout.getvalue()
                assert "Debug message" not in output
                assert "Info message" not in output
                assert "Warning message" in output
                assert "Error message" in output
    
    def test_error_level_logging(self):
        """Test ERROR level logging behavior"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("ERROR", log_path)
            
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                logger = logging.getLogger("test")
                logger.debug("Debug message")
                logger.info("Info message")
                logger.warning("Warning message")
                logger.error("Error message")
                logger.critical("Critical message")
                
                output = mock_stdout.getvalue()
                assert "Debug message" not in output
                assert "Info message" not in output
                assert "Warning message" not in output
                assert "Error message" in output
                assert "Critical message" in output


class TestErrorHandling:
    """Test suite for error handling scenarios"""
    
    def setup_method(self):
        """Setup for each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def teardown_method(self):
        """Cleanup after each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def test_invalid_log_level(self):
        """Test handling of invalid log level"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            with pytest.raises(AttributeError):
                setup_logging("INVALID_LEVEL", log_path)
    
    @patch('pathlib.Path.mkdir')
    def test_log_directory_creation_permission_error(self, mock_mkdir):
        """Test handling of permission error during directory creation"""
        mock_mkdir.side_effect = PermissionError("Permission denied")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "restricted"
            
            with pytest.raises(PermissionError):
                setup_logging("INFO", log_path)
    
    def test_file_handler_creation_with_readonly_directory(self):
        """Test file handler creation in read-only directory"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "readonly"
            log_path.mkdir()
            
            # Make directory read-only
            log_path.chmod(0o444)
            
            try:
                with pytest.raises(PermissionError):
                    setup_logging("INFO", log_path)
            finally:
                # Restore permissions for cleanup
                log_path.chmod(0o755)


class TestMultipleSetupCalls:
    """Test suite for multiple setup calls"""
    
    def setup_method(self):
        """Setup for each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def teardown_method(self):
        """Cleanup after each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def test_multiple_setup_calls(self):
        """Test that multiple setup calls work correctly"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            # First setup
            setup_logging("INFO", log_path)
            root_logger = logging.getLogger()
            first_handler_count = len(root_logger.handlers)
            
            # Second setup
            setup_logging("DEBUG", log_path)
            second_handler_count = len(root_logger.handlers)
            
            # Should have same number of handlers (old ones replaced)
            assert first_handler_count == second_handler_count
            assert root_logger.level == logging.DEBUG
    
    def test_setup_with_different_paths(self):
        """Test setup with different log paths"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path1 = Path(temp_dir) / "logs1"
            log_path2 = Path(temp_dir) / "logs2"
            
            # First setup
            setup_logging("INFO", log_path1)
            logger = logging.getLogger("test")
            logger.info("Message in first path")
            
            # Force flush
            for handler in logging.getLogger().handlers:
                handler.flush()
            
            # Second setup with different path
            setup_logging("INFO", log_path2)
            logger.info("Message in second path")
            
            # Force flush
            for handler in logging.getLogger().handlers:
                handler.flush()
            
            # Both log files should exist
            assert (log_path1 / "argus.log").exists()
            assert (log_path2 / "argus.log").exists()


class TestSecurityLogFiltering:
    """Test suite for security-related log filtering"""
    
    def setup_method(self):
        """Setup for each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def teardown_method(self):
        """Cleanup after each test method"""
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
    
    def test_sensitive_information_logging(self):
        """Test that sensitive information can be logged (for security audit)"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("INFO", log_path)
            
            logger = logging.getLogger("security")
            logger.info("Authentication attempt from IP: 192.168.1.100")
            logger.warning("Failed login attempt for user: admin")
            logger.error("Unauthorized access attempt detected")
            
            # Force flush
            for handler in logging.getLogger().handlers:
                handler.flush()
            
            # Verify logs are written (for security monitoring)
            log_file = log_path / "argus.log"
            assert log_file.exists()
            
            with open(log_file, 'r') as f:
                content = f.read()
            
            assert "Authentication attempt" in content
            assert "Failed login attempt" in content
            assert "Unauthorized access attempt" in content
    
    def test_audit_logging_format(self):
        """Test audit logging maintains proper JSON format"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir)
            
            setup_logging("INFO", log_path)
            
            logger = logging.getLogger("audit")
            logger.info("Security event", extra={
                "event_type": "authentication",
                "source_ip": "192.168.1.100",
                "user": "admin",
                "result": "success"
            })
            
            # Force flush
            for handler in logging.getLogger().handlers:
                handler.flush()
            
            log_file = log_path / "argus.log"
            with open(log_file, 'r') as f:
                log_entry = json.loads(f.read().strip())
            
            assert log_entry["message"] == "Security event"
            assert log_entry["event_type"] == "authentication"
            assert log_entry["source_ip"] == "192.168.1.100"
            assert log_entry["user"] == "admin"
            assert log_entry["result"] == "success"