"""
Logging configuration for Argus Scanner
"""
import logging
import sys
from pathlib import Path
from pythonjsonlogger import jsonlogger

def setup_logging(log_level: str, log_path: Path) -> None:
    """Configure application logging"""
    # Create log directory if it doesn't exist
    log_path.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler with human-readable format
    console_handler = logging.StreamHandler(sys.stdout)
    console_format = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)
    
    # File handler with JSON format for production
    file_handler = logging.FileHandler(log_path / "argus.log")
    json_format = jsonlogger.JsonFormatter()
    file_handler.setFormatter(json_format)
    root_logger.addHandler(file_handler)
    
    # Set third-party loggers to WARNING
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("watchdog").setLevel(logging.WARNING)