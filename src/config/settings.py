"""
Configuration settings for Argus Scanner
"""
import os
from pathlib import Path
from typing import List, Optional

class Settings:
    """Application settings with environment variable support"""
    
    def __init__(self):
        # Environment
        self.environment = os.getenv("ARGUS_ENV", "production")
        self.mock_mode = os.getenv("ARGUS_MOCK_MODE", "false").lower() == "true"
        
        # Database
        self.db_path = Path(os.getenv("ARGUS_DB_PATH", "/app/data/argus.db"))
        
        # Logging
        self.log_level = os.getenv("ARGUS_LOG_LEVEL", "INFO")
        self.log_path = Path(os.getenv("ARGUS_LOG_PATH", "/app/logs"))
        
        # Web server
        self.web_port = int(os.getenv("ARGUS_WEB_PORT", "8080"))
        self.secret_key = os.getenv("ARGUS_SECRET_KEY", "change-me-in-production")
        
        # Scanning configuration
        self.network_range = os.getenv("ARGUS_NETWORK_RANGE", "192.168.1.0/24")
        self.scan_interval = int(os.getenv("ARGUS_SCAN_INTERVAL", "3600"))
        self.scan_timeout = int(os.getenv("ARGUS_SCAN_TIMEOUT", "300"))
        self.max_parallel_scans = int(os.getenv("ARGUS_MAX_PARALLEL_SCANS", "5"))
        
        # Vulnerability detection
        self.cve_api_key = os.getenv("ARGUS_CVE_API_KEY")
        self.vulnerability_db_update_interval = int(os.getenv("ARGUS_VULN_DB_UPDATE_INTERVAL", "86400"))
        
        # Alerting
        self.alert_email_enabled = os.getenv("ARGUS_ALERT_EMAIL_ENABLED", "false").lower() == "true"
        self.alert_email_smtp_host = os.getenv("ARGUS_SMTP_HOST")
        self.alert_email_smtp_port = int(os.getenv("ARGUS_SMTP_PORT", "587"))
        self.alert_email_username = os.getenv("ARGUS_SMTP_USERNAME")
        self.alert_email_password = os.getenv("ARGUS_SMTP_PASSWORD")
        self.alert_email_from = os.getenv("ARGUS_ALERT_FROM")
        self.alert_email_to = os.getenv("ARGUS_ALERT_TO", "").split(",") if os.getenv("ARGUS_ALERT_TO") else []
        
        self.alert_slack_enabled = os.getenv("ARGUS_ALERT_SLACK_ENABLED", "false").lower() == "true"
        self.alert_slack_webhook = os.getenv("ARGUS_SLACK_WEBHOOK")
        
        # Security
        self.enable_exploit_testing = os.getenv("ARGUS_ENABLE_EXPLOIT_TESTING", "false").lower() == "true"
        self.authorized_networks = os.getenv("ARGUS_AUTHORIZED_NETWORKS", "").split(",") if os.getenv("ARGUS_AUTHORIZED_NETWORKS") else []
    
    @property
    def is_development(self) -> bool:
        return self.environment == "development"
    
    @property
    def is_production(self) -> bool:
        return self.environment == "production"