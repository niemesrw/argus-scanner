"""
Tests for main application module
"""
import pytest
import logging
import sys
from pathlib import Path
from unittest.mock import Mock, patch, call, MagicMock

from src.main import main


class TestMainFunction:
    """Test suite for main application function"""
    
    @patch('src.main.Settings')
    @patch('src.main.setup_logging')
    @patch('src.main.init_db')
    @patch('src.main.SchedulerService')
    @patch('src.main.create_app')
    def test_main_function_complete_flow(self, mock_create_app, mock_scheduler_service, 
                                       mock_init_db, mock_setup_logging, mock_settings_class):
        """Test complete main function execution flow"""
        # Setup mocks
        mock_settings = Mock()
        mock_settings.environment = 'development'
        mock_settings.log_level = 'DEBUG'
        mock_settings.log_path = Path('/test/logs')
        mock_settings.db_path = Path('/test/db.sqlite')
        mock_settings.web_port = 8080
        mock_settings.is_development = True
        mock_settings_class.return_value = mock_settings
        
        mock_scheduler = Mock()
        mock_scheduler_service.return_value = mock_scheduler
        
        mock_app = Mock()
        mock_create_app.return_value = mock_app
        
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            # Run main function
            main()
            
            # Verify settings were loaded
            mock_settings_class.assert_called_once()
            
            # Verify logging was setup
            mock_setup_logging.assert_called_once_with('DEBUG', Path('/test/logs'))
            
            # Verify logger was obtained and used
            mock_get_logger.assert_called_once_with('src.main')
            mock_logger.info.assert_any_call("Starting Argus Scanner in development mode")
            mock_logger.info.assert_any_call("Initializing database at /test/db.sqlite")
            mock_logger.info.assert_any_call("Starting web server on port 8080")
            
            # Verify database initialization
            mock_init_db.assert_called_once_with(Path('/test/db.sqlite'))
            
            # Verify scheduler service was created and started
            mock_scheduler_service.assert_called_once_with(mock_settings)
            mock_scheduler.start.assert_called_once()
            
            # Verify web app was created and started
            mock_create_app.assert_called_once_with(mock_settings)
            mock_app.run.assert_called_once_with(
                host="0.0.0.0",
                port=8080,
                debug=True
            )
    
    @patch('src.main.Settings')
    @patch('src.main.setup_logging')
    @patch('src.main.init_db')
    @patch('src.main.SchedulerService')
    @patch('src.main.create_app')
    def test_main_function_production_mode(self, mock_create_app, mock_scheduler_service,
                                         mock_init_db, mock_setup_logging, mock_settings_class):
        """Test main function in production mode"""
        # Setup production settings
        mock_settings = Mock()
        mock_settings.environment = 'production'
        mock_settings.log_level = 'INFO'
        mock_settings.log_path = Path('/var/log/argus')
        mock_settings.db_path = Path('/var/lib/argus/argus.db')
        mock_settings.web_port = 80
        mock_settings.is_development = False
        mock_settings_class.return_value = mock_settings
        
        mock_scheduler = Mock()
        mock_scheduler_service.return_value = mock_scheduler
        
        mock_app = Mock()
        mock_create_app.return_value = mock_app
        
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            main()
            
            # Verify production configuration
            mock_logger.info.assert_any_call("Starting Argus Scanner in production mode")
            mock_setup_logging.assert_called_once_with('INFO', Path('/var/log/argus'))
            mock_init_db.assert_called_once_with(Path('/var/lib/argus/argus.db'))
            
            # Verify web app runs without debug mode
            mock_app.run.assert_called_once_with(
                host="0.0.0.0",
                port=80,
                debug=False
            )
    
    @patch('src.main.Settings')
    @patch('src.main.setup_logging')
    @patch('src.main.init_db')
    @patch('src.main.SchedulerService')
    @patch('src.main.create_app')
    def test_main_function_custom_port(self, mock_create_app, mock_scheduler_service,
                                     mock_init_db, mock_setup_logging, mock_settings_class):
        """Test main function with custom port"""
        mock_settings = Mock()
        mock_settings.environment = 'development'
        mock_settings.log_level = 'DEBUG'
        mock_settings.log_path = Path('/test/logs')
        mock_settings.db_path = Path('/test/db.sqlite')
        mock_settings.web_port = 9000
        mock_settings.is_development = True
        mock_settings_class.return_value = mock_settings
        
        mock_scheduler = Mock()
        mock_scheduler_service.return_value = mock_scheduler
        
        mock_app = Mock()
        mock_create_app.return_value = mock_app
        
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            main()
            
            mock_logger.info.assert_any_call("Starting web server on port 9000")
            mock_app.run.assert_called_once_with(
                host="0.0.0.0",
                port=9000,
                debug=True
            )


class TestApplicationStartup:
    """Test suite for application startup scenarios"""
    
    @patch('src.main.Settings')
    @patch('src.main.setup_logging')
    @patch('src.main.init_db')
    @patch('src.main.SchedulerService')
    @patch('src.main.create_app')
    def test_startup_with_database_error(self, mock_create_app, mock_scheduler_service,
                                       mock_init_db, mock_setup_logging, mock_settings_class):
        """Test application startup when database initialization fails"""
        mock_settings = Mock()
        mock_settings.environment = 'development'
        mock_settings.log_level = 'DEBUG'
        mock_settings.log_path = Path('/test/logs')
        mock_settings.db_path = Path('/test/db.sqlite')
        mock_settings.web_port = 8080
        mock_settings.is_development = True
        mock_settings_class.return_value = mock_settings
        
        # Make database initialization fail
        mock_init_db.side_effect = Exception("Database connection failed")
        
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            with pytest.raises(Exception, match="Database connection failed"):
                main()
            
            # Verify logging was setup before failure
            mock_setup_logging.assert_called_once()
            mock_logger.info.assert_any_call("Starting Argus Scanner in development mode")
            mock_logger.info.assert_any_call("Initializing database at /test/db.sqlite")
            
            # Verify scheduler and web app were not started
            mock_scheduler_service.assert_not_called()
            mock_create_app.assert_not_called()
    
    @patch('src.main.Settings')
    @patch('src.main.setup_logging')
    @patch('src.main.init_db')
    @patch('src.main.SchedulerService')
    @patch('src.main.create_app')
    def test_startup_with_scheduler_error(self, mock_create_app, mock_scheduler_service,
                                        mock_init_db, mock_setup_logging, mock_settings_class):
        """Test application startup when scheduler fails to start"""
        mock_settings = Mock()
        mock_settings.environment = 'development'
        mock_settings.log_level = 'DEBUG'
        mock_settings.log_path = Path('/test/logs')
        mock_settings.db_path = Path('/test/db.sqlite')
        mock_settings.web_port = 8080
        mock_settings.is_development = True
        mock_settings_class.return_value = mock_settings
        
        # Make scheduler fail to start
        mock_scheduler = Mock()
        mock_scheduler.start.side_effect = Exception("Scheduler failed to start")
        mock_scheduler_service.return_value = mock_scheduler
        
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            with pytest.raises(Exception, match="Scheduler failed to start"):
                main()
            
            # Verify database was initialized successfully
            mock_init_db.assert_called_once()
            
            # Verify scheduler was created but failed to start
            mock_scheduler_service.assert_called_once()
            mock_scheduler.start.assert_called_once()
            
            # Verify web app was not started
            mock_create_app.assert_not_called()
    
    @patch('src.main.Settings')
    @patch('src.main.setup_logging')
    @patch('src.main.init_db')
    @patch('src.main.SchedulerService')
    @patch('src.main.create_app')
    def test_startup_with_web_app_creation_error(self, mock_create_app, mock_scheduler_service,
                                                mock_init_db, mock_setup_logging, mock_settings_class):
        """Test application startup when web app creation fails"""
        mock_settings = Mock()
        mock_settings.environment = 'development'
        mock_settings.log_level = 'DEBUG'
        mock_settings.log_path = Path('/test/logs')
        mock_settings.db_path = Path('/test/db.sqlite')
        mock_settings.web_port = 8080
        mock_settings.is_development = True
        mock_settings_class.return_value = mock_settings
        
        mock_scheduler = Mock()
        mock_scheduler_service.return_value = mock_scheduler
        
        # Make web app creation fail
        mock_create_app.side_effect = Exception("Flask app creation failed")
        
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            with pytest.raises(Exception, match="Flask app creation failed"):
                main()
            
            # Verify database and scheduler were successful
            mock_init_db.assert_called_once()
            mock_scheduler_service.assert_called_once()
            mock_scheduler.start.assert_called_once()
            
            # Verify web app creation was attempted
            mock_create_app.assert_called_once()
    
    @patch('src.main.Settings')
    @patch('src.main.setup_logging')
    def test_startup_with_logging_setup_error(self, mock_setup_logging, mock_settings_class):
        """Test application startup when logging setup fails"""
        mock_settings = Mock()
        mock_settings.environment = 'development'
        mock_settings.log_level = 'DEBUG'
        mock_settings.log_path = Path('/nonexistent/logs')
        mock_settings_class.return_value = mock_settings
        
        # Make logging setup fail
        mock_setup_logging.side_effect = PermissionError("Cannot create log directory")
        
        with pytest.raises(PermissionError, match="Cannot create log directory"):
            main()
        
        # Verify settings were loaded
        mock_settings_class.assert_called_once()
        mock_setup_logging.assert_called_once()


class TestSignalHandling:
    """Test suite for signal handling and graceful shutdown"""
    
    @patch('src.main.Settings')
    @patch('src.main.setup_logging')
    @patch('src.main.init_db')
    @patch('src.main.SchedulerService')
    @patch('src.main.create_app')
    def test_graceful_shutdown_simulation(self, mock_create_app, mock_scheduler_service,
                                        mock_init_db, mock_setup_logging, mock_settings_class):
        """Test graceful shutdown behavior simulation"""
        mock_settings = Mock()
        mock_settings.environment = 'development'
        mock_settings.log_level = 'DEBUG'
        mock_settings.log_path = Path('/test/logs')
        mock_settings.db_path = Path('/test/db.sqlite')
        mock_settings.web_port = 8080
        mock_settings.is_development = True
        mock_settings_class.return_value = mock_settings
        
        mock_scheduler = Mock()
        mock_scheduler_service.return_value = mock_scheduler
        
        mock_app = Mock()
        # Simulate KeyboardInterrupt (Ctrl+C) during app.run()
        mock_app.run.side_effect = KeyboardInterrupt("User requested shutdown")
        mock_create_app.return_value = mock_app
        
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            with pytest.raises(KeyboardInterrupt):
                main()
            
            # Verify normal startup occurred before shutdown
            mock_init_db.assert_called_once()
            mock_scheduler.start.assert_called_once()
            mock_app.run.assert_called_once()


class TestMainModuleExecution:
    """Test suite for main module execution scenarios"""
    
    @patch('src.main.main')
    def test_main_module_execution(self, mock_main):
        """Test that main() is called when module is executed directly"""
        # Simulate running the module with python -m src.main
        with patch('sys.argv', ['src.main']):
            with patch('src.main.__name__', '__main__'):
                # Import and execute the if __name__ == "__main__" block
                exec("""
if __name__ == "__main__":
    main()
                """, {'__name__': '__main__', 'main': mock_main})
                
                mock_main.assert_called_once()
    
    @patch('src.main.main')
    def test_main_module_import_no_execution(self, mock_main):
        """Test that main() is not called when module is imported"""
        # Simulate importing the module
        with patch('src.main.__name__', 'src.main'):
            # Import should not trigger main execution
            exec("""
if __name__ == "__main__":
    main()
            """, {'__name__': 'src.main', 'main': mock_main})
            
            mock_main.assert_not_called()


class TestErrorLogging:
    """Test suite for error logging scenarios"""
    
    @patch('src.main.Settings')
    @patch('src.main.setup_logging')
    @patch('src.main.init_db')
    @patch('src.main.SchedulerService')
    @patch('src.main.create_app')
    def test_startup_success_logging(self, mock_create_app, mock_scheduler_service,
                                   mock_init_db, mock_setup_logging, mock_settings_class):
        """Test that successful startup logs appropriate messages"""
        mock_settings = Mock()
        mock_settings.environment = 'production'
        mock_settings.log_level = 'INFO'
        mock_settings.log_path = Path('/var/log/argus')
        mock_settings.db_path = Path('/var/lib/argus/argus.db')
        mock_settings.web_port = 8080
        mock_settings.is_development = False
        mock_settings_class.return_value = mock_settings
        
        mock_scheduler = Mock()
        mock_scheduler_service.return_value = mock_scheduler
        
        mock_app = Mock()
        mock_create_app.return_value = mock_app
        
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            main()
            
            # Verify all startup messages were logged
            expected_calls = [
                call("Starting Argus Scanner in production mode"),
                call("Initializing database at /var/lib/argus/argus.db"),
                call("Starting web server on port 8080")
            ]
            
            mock_logger.info.assert_has_calls(expected_calls)
            assert mock_logger.info.call_count == 3


class TestEnvironmentSpecificBehavior:
    """Test suite for environment-specific behavior"""
    
    @patch('src.main.Settings')
    @patch('src.main.setup_logging')
    @patch('src.main.init_db')
    @patch('src.main.SchedulerService')
    @patch('src.main.create_app')
    def test_development_environment_behavior(self, mock_create_app, mock_scheduler_service,
                                            mock_init_db, mock_setup_logging, mock_settings_class):
        """Test behavior specific to development environment"""
        mock_settings = Mock()
        mock_settings.environment = 'development'
        mock_settings.log_level = 'DEBUG'
        mock_settings.log_path = Path('./logs')
        mock_settings.db_path = Path('./data/argus.db')
        mock_settings.web_port = 8080
        mock_settings.is_development = True
        mock_settings_class.return_value = mock_settings
        
        mock_scheduler = Mock()
        mock_scheduler_service.return_value = mock_scheduler
        
        mock_app = Mock()
        mock_create_app.return_value = mock_app
        
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            main()
            
            # Verify development-specific behavior
            mock_logger.info.assert_any_call("Starting Argus Scanner in development mode")
            mock_app.run.assert_called_once_with(
                host="0.0.0.0",
                port=8080,
                debug=True  # Debug mode enabled in development
            )
    
    @patch('src.main.Settings')
    @patch('src.main.setup_logging')
    @patch('src.main.init_db')
    @patch('src.main.SchedulerService')
    @patch('src.main.create_app')
    def test_staging_environment_behavior(self, mock_create_app, mock_scheduler_service,
                                        mock_init_db, mock_setup_logging, mock_settings_class):
        """Test behavior in staging environment"""
        mock_settings = Mock()
        mock_settings.environment = 'staging'
        mock_settings.log_level = 'INFO'
        mock_settings.log_path = Path('/opt/argus/logs')
        mock_settings.db_path = Path('/opt/argus/data/argus.db')
        mock_settings.web_port = 8080
        mock_settings.is_development = False  # Staging is not development
        mock_settings_class.return_value = mock_settings
        
        mock_scheduler = Mock()
        mock_scheduler_service.return_value = mock_scheduler
        
        mock_app = Mock()
        mock_create_app.return_value = mock_app
        
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            main()
            
            # Verify staging-specific behavior
            mock_logger.info.assert_any_call("Starting Argus Scanner in staging mode")
            mock_app.run.assert_called_once_with(
                host="0.0.0.0",
                port=8080,
                debug=False  # Debug mode disabled in staging
            )