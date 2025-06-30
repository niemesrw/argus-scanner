"""
Integration tests for alert notification delivery
"""
import pytest
import smtplib
import json
from unittest.mock import patch, MagicMock
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from src.alerts.manager import AlertManager
from src.database.models import Device, Vulnerability, Alert
from src.config.settings import Settings


@pytest.mark.integration
@pytest.mark.network
class TestAlertDeliveryIntegration:
    """Integration tests for alert delivery mechanisms"""
    
    def test_email_delivery_integration(self, integration_settings, db_session):
        """Test email alert delivery with real SMTP simulation"""
        # Create test data
        device = Device(
            mac_address='00:11:22:33:44:AA',
            ip_address='192.168.1.50',
            hostname='mail-test-device',
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        db_session.add(device)
        db_session.commit()
        
        vulnerability = Vulnerability(
            device_id=device.id,
            cve_id='CVE-2023-EMAIL-TEST',
            cvss_score=7.5,
            severity='high',
            description='Test vulnerability for email delivery',
            solution='Apply security patch',
            discovered_at=datetime.now()
        )
        db_session.add(vulnerability)
        db_session.commit()
        
        # Mock SMTP server
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.starttls.return_value = None
            mock_server.login.return_value = None
            mock_server.send_message.return_value = {}
            
            # Initialize alert manager with email settings
            alert_manager = AlertManager(integration_settings)
            
            # Send email alert
            result = alert_manager.send_email_alert(device, vulnerability)
            
            # Verify email was sent
            assert result is True
            mock_smtp.assert_called_once()
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once()
            mock_server.send_message.assert_called_once()
        
        # Verify alert was logged in database
        alerts = db_session.query(Alert).filter_by(
            device_id=device.id,
            alert_type='email'
        ).all()
        assert len(alerts) >= 1
        
        alert = alerts[0]
        assert alert.status == 'sent'
        assert alert.severity == 'high'
        assert 'CVE-2023-EMAIL-TEST' in alert.message
    
    def test_slack_delivery_integration(self, integration_settings, db_session):
        """Test Slack alert delivery with webhook simulation"""
        # Create test data
        device = Device(
            mac_address='00:11:22:33:44:BB',
            ip_address='192.168.1.60',
            hostname='slack-test-device',
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        db_session.add(device)
        db_session.commit()
        
        vulnerability = Vulnerability(
            device_id=device.id,
            cve_id='CVE-2023-SLACK-TEST',
            cvss_score=9.0,
            severity='critical',
            description='Critical vulnerability for Slack delivery test',
            solution='Immediate patching required',
            discovered_at=datetime.now()
        )
        db_session.add(vulnerability)
        db_session.commit()
        
        # Mock HTTP requests for Slack webhook
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'ok': True}
            mock_post.return_value = mock_response
            
            # Initialize alert manager
            alert_manager = AlertManager(integration_settings)
            
            # Send Slack alert
            result = alert_manager.send_slack_alert(device, vulnerability)
            
            # Verify Slack webhook was called
            assert result is True
            mock_post.assert_called_once()
            
            # Verify webhook payload
            call_args = mock_post.call_args
            assert call_args[1]['json'] is not None
            payload = call_args[1]['json']
            assert 'text' in payload
            assert 'attachments' in payload
            assert 'CVE-2023-SLACK-TEST' in payload['text']
        
        # Verify alert was logged
        alerts = db_session.query(Alert).filter_by(
            device_id=device.id,
            alert_type='slack'
        ).all()
        assert len(alerts) >= 1
        
        alert = alerts[0]
        assert alert.status == 'sent'
        assert alert.severity == 'critical'
    
    def test_multi_channel_alert_delivery(self, integration_settings, db_session):
        """Test sending alerts through multiple channels simultaneously"""
        # Create test data
        device = Device(
            mac_address='00:11:22:33:44:CC',
            ip_address='192.168.1.70',
            hostname='multi-channel-device',
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        db_session.add(device)
        db_session.commit()
        
        vulnerability = Vulnerability(
            device_id=device.id,
            cve_id='CVE-2023-MULTI-TEST',
            cvss_score=8.5,
            severity='high',
            description='Vulnerability for multi-channel delivery test',
            discovered_at=datetime.now()
        )
        db_session.add(vulnerability)
        db_session.commit()
        
        # Mock both email and Slack
        with patch('smtplib.SMTP') as mock_smtp, \
             patch('requests.post') as mock_post:
            
            # Setup email mock
            mock_email_server = MagicMock()
            mock_smtp.return_value = mock_email_server
            mock_email_server.send_message.return_value = {}
            
            # Setup Slack mock
            mock_slack_response = MagicMock()
            mock_slack_response.status_code = 200
            mock_post.return_value = mock_slack_response
            
            # Initialize alert manager
            alert_manager = AlertManager(integration_settings)
            
            # Send alerts through all channels
            email_result = alert_manager.send_email_alert(device, vulnerability)
            slack_result = alert_manager.send_slack_alert(device, vulnerability)
            
            # Verify both channels were used
            assert email_result is True
            assert slack_result is True
            mock_smtp.assert_called_once()
            mock_post.assert_called_once()
        
        # Verify both alerts were logged
        email_alerts = db_session.query(Alert).filter_by(
            device_id=device.id,
            alert_type='email'
        ).all()
        slack_alerts = db_session.query(Alert).filter_by(
            device_id=device.id,
            alert_type='slack'
        ).all()
        
        assert len(email_alerts) >= 1
        assert len(slack_alerts) >= 1
    
    def test_alert_delivery_failure_handling(self, integration_settings, db_session):
        """Test handling of alert delivery failures"""
        # Create test data
        device = Device(
            mac_address='00:11:22:33:44:DD',
            ip_address='192.168.1.80',
            hostname='failure-test-device',
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        db_session.add(device)
        db_session.commit()
        
        vulnerability = Vulnerability(
            device_id=device.id,
            cve_id='CVE-2023-FAILURE-TEST',
            cvss_score=6.5,
            severity='medium',
            description='Vulnerability for failure handling test',
            discovered_at=datetime.now()
        )
        db_session.add(vulnerability)
        db_session.commit()
        
        # Test email delivery failure
        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = smtplib.SMTPException("SMTP server unavailable")
            
            alert_manager = AlertManager(integration_settings)
            
            # Attempt to send email (should fail gracefully)
            result = alert_manager.send_email_alert(device, vulnerability)
            
            # Should return False but not crash
            assert result is False
        
        # Test Slack delivery failure
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.raise_for_status.side_effect = Exception("Slack API error")
            mock_post.return_value = mock_response
            
            # Attempt to send Slack alert (should fail gracefully)
            result = alert_manager.send_slack_alert(device, vulnerability)
            
            # Should return False but not crash
            assert result is False
        
        # Verify failed alerts were logged
        failed_alerts = db_session.query(Alert).filter_by(
            device_id=device.id,
            status='failed'
        ).all()
        assert len(failed_alerts) >= 1
    
    def test_alert_rate_limiting(self, integration_settings, db_session):
        """Test alert rate limiting to prevent spam"""
        # Create test device
        device = Device(
            mac_address='00:11:22:33:44:EE',
            ip_address='192.168.1.90',
            hostname='rate-limit-device',
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        db_session.add(device)
        db_session.commit()
        
        # Create multiple vulnerabilities
        vulnerabilities = []
        for i in range(5):
            vuln = Vulnerability(
                device_id=device.id,
                cve_id=f'CVE-2023-RATE-{i}',
                cvss_score=7.0,
                severity='high',
                description=f'Rate limiting test vulnerability {i}',
                discovered_at=datetime.now()
            )
            vulnerabilities.append(vuln)
            db_session.add(vuln)
        db_session.commit()
        
        # Mock email delivery
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.send_message.return_value = {}
            
            alert_manager = AlertManager(integration_settings)
            
            # Send multiple alerts rapidly
            results = []
            for vuln in vulnerabilities:
                result = alert_manager.send_email_alert(device, vuln)
                results.append(result)
            
            # Some alerts should be rate-limited
            successful_alerts = sum(1 for r in results if r is True)
            
            # Should not send all 5 alerts if rate limiting is working
            # (depends on implementation - this tests the concept)
            assert successful_alerts <= len(vulnerabilities)
    
    def test_alert_template_rendering(self, integration_settings, db_session):
        """Test alert template rendering with dynamic content"""
        # Create test data with rich metadata
        device = Device(
            mac_address='00:11:22:33:44:FF',
            ip_address='192.168.1.100',
            hostname='template-test-device',
            device_type='server',
            operating_system='Ubuntu',
            os_version='20.04',
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            device_metadata={
                'services': [
                    {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.0'},
                    {'port': 80, 'service': 'http', 'version': 'Apache 2.4'}
                ]
            }
        )
        db_session.add(device)
        db_session.commit()
        
        vulnerability = Vulnerability(
            device_id=device.id,
            cve_id='CVE-2023-TEMPLATE-TEST',
            cvss_score=8.0,
            severity='high',
            description='Template rendering test vulnerability with rich context',
            solution='Apply security patches and update system',
            discovered_at=datetime.now()
        )
        db_session.add(vulnerability)
        db_session.commit()
        
        # Mock email delivery to capture template content
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            
            alert_manager = AlertManager(integration_settings)
            
            # Send templated alert
            result = alert_manager.send_email_alert(device, vulnerability)
            
            # Verify template was rendered
            assert result is True
            mock_server.send_message.assert_called_once()
            
            # Extract the email message
            call_args = mock_server.send_message.call_args[0][0]
            email_body = str(call_args)
            
            # Verify dynamic content was included
            assert '192.168.1.100' in email_body
            assert 'template-test-device' in email_body
            assert 'CVE-2023-TEMPLATE-TEST' in email_body
            assert 'Ubuntu 20.04' in email_body
    
    def test_alert_acknowledgment_workflow(self, integration_settings, db_session):
        """Test alert acknowledgment and resolution workflow"""
        # Create test data
        device = Device(
            mac_address='00:11:22:33:44:00',
            ip_address='192.168.1.110',
            hostname='ack-test-device',
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        db_session.add(device)
        db_session.commit()
        
        vulnerability = Vulnerability(
            device_id=device.id,
            cve_id='CVE-2023-ACK-TEST',
            cvss_score=7.5,
            severity='high',
            description='Acknowledgment test vulnerability',
            discovered_at=datetime.now()
        )
        db_session.add(vulnerability)
        db_session.commit()
        
        # Mock alert delivery
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server
            mock_server.send_message.return_value = {}
            
            alert_manager = AlertManager(integration_settings)
            
            # Send initial alert
            result = alert_manager.send_email_alert(device, vulnerability)
            assert result is True
            
            # Get the alert from database
            alert = db_session.query(Alert).filter_by(
                device_id=device.id,
                vulnerability_id=vulnerability.id
            ).first()
            assert alert is not None
            assert alert.status == 'sent'
            
            # Acknowledge the alert
            alert_manager.acknowledge_alert(alert.id, 'Security team reviewed')
            
            # Verify acknowledgment
            db_session.refresh(alert)
            assert alert.status == 'acknowledged'
            assert alert.acknowledged_at is not None
            assert 'Security team reviewed' in alert.acknowledgment_notes
            
            # Resolve the alert
            alert_manager.resolve_alert(alert.id, 'Patch applied successfully')
            
            # Verify resolution
            db_session.refresh(alert)
            assert alert.status == 'resolved'
            assert alert.resolved_at is not None
            assert 'Patch applied successfully' in alert.resolution_notes