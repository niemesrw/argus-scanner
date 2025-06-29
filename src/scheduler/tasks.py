"""
Task scheduling for continuous network monitoring
"""
import logging
from datetime import datetime, timedelta
from typing import Optional
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from src.config.settings import Settings
from src.scanner.discovery import NetworkDiscovery
from src.scanner.vulnerability import VulnerabilityScanner
from src.database.models import Device, Scan, ScanType, get_db_session
from src.alerts.manager import AlertManager

logger = logging.getLogger(__name__)

class SchedulerService:
    """Manages scheduled scanning tasks"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.scheduler = BackgroundScheduler()
        self.discovery = NetworkDiscovery(settings)
        self.vuln_scanner = VulnerabilityScanner(settings)
        self.alert_manager = AlertManager(settings)
        self.db = get_db_session(settings.db_path)
        
    def start(self):
        """Start the scheduler"""
        logger.info("Starting scheduler service")
        
        # Schedule network discovery
        self.scheduler.add_job(
            func=self.run_network_discovery,
            trigger=IntervalTrigger(seconds=self.settings.scan_interval),
            id='network_discovery',
            name='Network Discovery Scan',
            replace_existing=True
        )
        
        # Schedule vulnerability scanning (less frequent)
        self.scheduler.add_job(
            func=self.run_vulnerability_scan,
            trigger=IntervalTrigger(seconds=self.settings.scan_interval * 2),
            id='vulnerability_scan',
            name='Vulnerability Scan',
            replace_existing=True
        )
        
        # Schedule device cleanup (mark inactive devices)
        self.scheduler.add_job(
            func=self.cleanup_inactive_devices,
            trigger=IntervalTrigger(hours=24),
            id='device_cleanup',
            name='Device Cleanup',
            replace_existing=True
        )
        
        # Schedule vulnerability database update
        if self.settings.cve_api_key:
            self.scheduler.add_job(
                func=self.update_vulnerability_database,
                trigger=IntervalTrigger(
                    seconds=self.settings.vulnerability_db_update_interval
                ),
                id='vuln_db_update',
                name='Vulnerability Database Update',
                replace_existing=True
            )
        
        self.scheduler.start()
        
        # Run initial discovery
        self.run_network_discovery()
        
    def stop(self):
        """Stop the scheduler"""
        logger.info("Stopping scheduler service")
        self.scheduler.shutdown()
    
    def run_network_discovery(self):
        """Run network discovery scan"""
        logger.info("Starting scheduled network discovery")
        
        # Create scan record
        scan = Scan(
            scan_type=ScanType.DISCOVERY,
            target_range=self.settings.network_range,
            started_at=datetime.utcnow()
        )
        self.db.add(scan)
        self.db.commit()
        
        try:
            # Perform discovery
            discovered_devices = self.discovery.discover_devices()
            
            # Update scan record
            scan.completed_at = datetime.utcnow()
            scan.status = 'completed'
            scan.total_hosts = len(discovered_devices)
            scan.hosts_scanned = len(discovered_devices)
            
            # Check for new devices
            self._check_new_devices(discovered_devices)
            
            # Perform deep scan on new or recently changed devices
            for device_info in discovered_devices:
                device = self.db.query(Device).filter_by(
                    ip_address=device_info['ip_address']
                ).first()
                
                if device and self._should_deep_scan(device):
                    self.discovery.deep_scan_device(device_info['ip_address'])
            
            self.db.commit()
            logger.info(f"Network discovery completed. Found {len(discovered_devices)} devices")
            
        except Exception as e:
            logger.error(f"Error during network discovery: {e}")
            scan.status = 'failed'
            scan.error_message = str(e)
            self.db.commit()
    
    def run_vulnerability_scan(self):
        """Run vulnerability scan on all active devices"""
        logger.info("Starting scheduled vulnerability scan")
        
        # Create scan record
        scan = Scan(
            scan_type=ScanType.VULNERABILITY,
            target_range=self.settings.network_range,
            started_at=datetime.utcnow()
        )
        self.db.add(scan)
        self.db.commit()
        
        try:
            # Get all active devices
            active_devices = self.db.query(Device).filter_by(is_active=True).all()
            
            scan.total_hosts = len(active_devices)
            vulnerabilities_found = 0
            
            for device in active_devices:
                logger.info(f"Scanning vulnerabilities for {device.ip_address}")
                
                vulns = self.vuln_scanner.scan_device_vulnerabilities(device.id)
                vulnerabilities_found += len(vulns)
                
                # Check for critical vulnerabilities
                critical_vulns = [v for v in vulns if v.get('severity') == 'critical']
                if critical_vulns:
                    self.alert_manager.send_critical_vulnerability_alert(
                        device, critical_vulns
                    )
                
                scan.hosts_scanned += 1
            
            scan.completed_at = datetime.utcnow()
            scan.status = 'completed'
            scan.vulnerabilities_found = vulnerabilities_found
            
            self.db.commit()
            logger.info(f"Vulnerability scan completed. Found {vulnerabilities_found} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error during vulnerability scan: {e}")
            scan.status = 'failed'
            scan.error_message = str(e)
            self.db.commit()
    
    def cleanup_inactive_devices(self):
        """Mark devices as inactive if not seen recently"""
        logger.info("Running device cleanup")
        
        try:
            # Mark devices as inactive if not seen in 7 days
            cutoff_date = datetime.utcnow() - timedelta(days=7)
            
            inactive_devices = self.db.query(Device).filter(
                Device.last_seen < cutoff_date,
                Device.is_active == True
            ).all()
            
            for device in inactive_devices:
                device.is_active = False
                logger.info(f"Marking device {device.ip_address} as inactive")
            
            self.db.commit()
            logger.info(f"Marked {len(inactive_devices)} devices as inactive")
            
        except Exception as e:
            logger.error(f"Error during device cleanup: {e}")
            self.db.rollback()
    
    def update_vulnerability_database(self):
        """Update local vulnerability database"""
        logger.info("Updating vulnerability database")
        
        # In a production system, this would:
        # 1. Download latest CVE data from NVD
        # 2. Update exploit availability information
        # 3. Update vulnerability signatures
        # For now, just log the action
        
        logger.info("Vulnerability database update completed")
    
    def _should_deep_scan(self, device: Device) -> bool:
        """Determine if device should be deep scanned"""
        # Deep scan if:
        # 1. Never been deep scanned (no services)
        # 2. Risk score is high
        # 3. Recently discovered (within last hour)
        
        if not device.services:
            return True
        
        if device.risk_score > 50:
            return True
        
        if device.first_seen > datetime.utcnow() - timedelta(hours=1):
            return True
        
        return False
    
    def _check_new_devices(self, discovered_devices: list):
        """Check for new devices and send alerts"""
        for device_info in discovered_devices:
            device = self.db.query(Device).filter_by(
                mac_address=device_info.get('mac_address')
            ).first()
            
            if device and device.first_seen > datetime.utcnow() - timedelta(minutes=5):
                # New device discovered
                self.alert_manager.send_new_device_alert(device_info)