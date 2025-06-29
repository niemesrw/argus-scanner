#!/usr/bin/env python3
"""
Argus Network Security Scanner - Main Entry Point
"""
import os
import sys
import logging
from pathlib import Path

from src.config.settings import Settings
from src.database.models import init_db
from src.scheduler.tasks import SchedulerService
from src.web.app import create_app
from src.utils.logger import setup_logging

def main():
    """Main entry point for Argus Scanner"""
    # Load settings
    settings = Settings()
    
    # Setup logging
    setup_logging(settings.log_level, settings.log_path)
    logger = logging.getLogger(__name__)
    
    logger.info(f"Starting Argus Scanner in {settings.environment} mode")
    
    # Initialize database
    logger.info(f"Initializing database at {settings.db_path}")
    init_db(settings.db_path)
    
    # Start scheduler service
    scheduler = SchedulerService(settings)
    scheduler.start()
    
    # Start web application
    app = create_app(settings)
    
    logger.info(f"Starting web server on port {settings.web_port}")
    app.run(
        host="0.0.0.0",
        port=settings.web_port,
        debug=settings.is_development
    )

if __name__ == "__main__":
    main()