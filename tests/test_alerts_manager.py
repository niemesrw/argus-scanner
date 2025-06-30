"""
Tests for alerts manager module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import smtplib
import requests

from src.alerts.manager import AlertManager
from src.database.models import Alert, Severity, Device
from src.config.settings import Settings


@pytest.fixture
def mock_settings():
    """Create mock settings for testing"""
    settings = Mock(spec=Settings)
    settings.db_path = ":memory:"
    settings.environment = "development"
    settings.is_production = False
    settings.network_range = "192.168.1.0/24"
    settings.web_port = 8080

    # Email settings
    settings.alert_email_enabled = True
    settings.alert_email_smtp_host = "smtp.example.com"
    settings.alert_email_smtp_port = 587
    settings.alert_email_from = "alerts@example.com"
    settings.alert_email_to = ["admin@example.com", "security@example.com"]
    settings.alert_email_username = "alerts@example.com"
    settings.alert_email_password = "password123"

    # Slack settings
    settings.alert_slack_enabled = True
    settings.alert_slack_webhook = (
        "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    )

    return settings


@pytest.fixture
def mock_db_session():
    """Create mock database session"""
    db = Mock()
    db.query.return_value = Mock()
    db.add = Mock()
    db.commit = Mock()
    db.rollback = Mock()
    return db


@pytest.fixture
def alert_manager(mock_settings):
    """Create alert manager instance with mocked dependencies"""
    with patch("src.alerts.manager.get_db_session") as mock_get_db:
        mock_db = Mock()
        mock_get_db.return_value = mock_db

        manager = AlertManager(mock_settings)
        manager.db = mock_db
        return manager


@pytest.fixture
def sample_device():
    """Create sample device for testing"""
    device = Mock(spec=Device)
    device.id = 1
    device.ip_address = "192.168.1.100"
    device.hostname = "server.example.com"
    device.mac_address = "00:11:22:33:44:55"
    device.risk_score = 75.0
    return device


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerabilities for testing"""
    return [
        {
            "name": "Remote Code Execution Vulnerability",
            "cve_id": "CVE-2023-1234",
            "description": "Critical remote code execution vulnerability that allows attackers to execute arbitrary code on the target system.",
        },
        {
            "name": "SQL Injection Vulnerability",
            "cve_id": "CVE-2023-5678",
            "description": "SQL injection vulnerability in user authentication that could lead to database compromise.",
        },
    ]


@pytest.fixture
def sample_alert():
    """Create sample alert for testing"""
    alert = Mock(spec=Alert)
    alert.id = 1
    alert.severity = Severity.CRITICAL
    alert.title = "Test Alert"
    alert.message = "This is a test alert message"
    alert.created_at = datetime.utcnow()
    alert.notification_sent = False
    alert.acknowledged = False
    alert.acknowledged_at = None
    alert.acknowledged_by = None
    alert.alert_metadata = {}
    return alert


class TestAlertManagerInitialization:
    """Test alert manager initialization"""

    def test_init(self, mock_settings):
        """Test alert manager initialization"""
        with patch("src.alerts.manager.get_db_session") as mock_get_db:
            manager = AlertManager(mock_settings)

            assert manager.settings == mock_settings
            mock_get_db.assert_called_once_with(mock_settings.db_path)


class TestCriticalVulnerabilityAlerts:
    """Test critical vulnerability alert functionality"""

    def test_send_critical_vulnerability_alert(
        self, alert_manager, sample_device, sample_vulnerabilities
    ):
        """Test sending critical vulnerability alert"""
        with patch("src.alerts.manager.Alert") as mock_alert_class, patch.object(
            alert_manager, "_send_notifications"
        ) as mock_send_notifications:

            mock_alert = Mock()
            mock_alert_class.return_value = mock_alert

            alert_manager.send_critical_vulnerability_alert(
                sample_device, sample_vulnerabilities
            )

            # Verify alert creation
            mock_alert_class.assert_called_once()
            create_call = mock_alert_class.call_args
            assert create_call[1]["severity"] == Severity.CRITICAL
            assert "Critical Vulnerabilities Found" in create_call[1]["title"]
            assert sample_device.ip_address in create_call[1]["message"]
            assert create_call[1]["alert_metadata"]["device_id"] == sample_device.id
            assert create_call[1]["alert_metadata"]["vulnerability_count"] == 2

            # Verify database operations
            alert_manager.db.add.assert_called_once_with(mock_alert)
            alert_manager.db.commit.assert_called_once()

            # Verify notifications sent
            mock_send_notifications.assert_called_once_with(mock_alert)

    def test_critical_vulnerability_alert_message_format(
        self, alert_manager, sample_device, sample_vulnerabilities
    ):
        """Test critical vulnerability alert message formatting"""
        with patch("src.alerts.manager.Alert") as mock_alert_class, patch.object(
            alert_manager, "_send_notifications"
        ):

            alert_manager.send_critical_vulnerability_alert(
                sample_device, sample_vulnerabilities
            )

            create_call = mock_alert_class.call_args
            message = create_call[1]["message"]

            # Verify message contains device details
            assert sample_device.hostname in message
            assert sample_device.ip_address in message
            assert sample_device.mac_address in message
            assert str(sample_device.risk_score) in message

            # Verify message contains vulnerability details
            assert "Remote Code Execution Vulnerability" in message
            assert "CVE-2023-1234" in message
            assert "CVE-2023-5678" in message

    def test_critical_vulnerability_alert_no_hostname(
        self, alert_manager, sample_device, sample_vulnerabilities
    ):
        """Test critical vulnerability alert with device without hostname"""
        sample_device.hostname = None

        with patch("src.alerts.manager.Alert") as mock_alert_class, patch.object(
            alert_manager, "_send_notifications"
        ):

            alert_manager.send_critical_vulnerability_alert(
                sample_device, sample_vulnerabilities
            )

            create_call = mock_alert_class.call_args
            title = create_call[1]["title"]
            message = create_call[1]["message"]

            # Should use IP address when hostname is None
            assert sample_device.ip_address in title
            assert sample_device.ip_address in message


class TestNewDeviceAlerts:
    """Test new device discovery alert functionality"""

    def test_send_new_device_alert(self, alert_manager):
        """Test sending new device alert"""
        device_info = {
            "ip_address": "192.168.1.200",
            "mac_address": "00:11:22:33:44:99",
            "hostname": "new-device.example.com",
            "manufacturer": "Dell Inc.",
            "last_seen": "2023-06-30 12:00:00",
        }

        with patch("src.alerts.manager.Alert") as mock_alert_class, patch.object(
            alert_manager, "_send_notifications"
        ) as mock_send_notifications:

            mock_alert = Mock()
            mock_alert_class.return_value = mock_alert

            alert_manager.send_new_device_alert(device_info)

            # Verify alert creation
            mock_alert_class.assert_called_once()
            create_call = mock_alert_class.call_args
            assert create_call[1]["severity"] == Severity.INFO
            assert "New Device Discovered" in create_call[1]["title"]
            assert device_info["ip_address"] in create_call[1]["message"]
            assert create_call[1]["alert_metadata"] == device_info

            # Verify database operations
            alert_manager.db.add.assert_called_once_with(mock_alert)
            alert_manager.db.commit.assert_called_once()

            # Should not send notifications in development
            mock_send_notifications.assert_not_called()

    def test_send_new_device_alert_production(self, alert_manager):
        """Test new device alert sends notifications in production"""
        alert_manager.settings.environment = "production"
        device_info = {
            "ip_address": "192.168.1.200",
            "last_seen": "2023-06-30 12:00:00",
        }

        with patch("src.alerts.manager.Alert") as mock_alert_class, patch.object(
            alert_manager, "_send_notifications"
        ) as mock_send_notifications:

            mock_alert = Mock()
            mock_alert_class.return_value = mock_alert

            alert_manager.send_new_device_alert(device_info)

            # Should send notifications in production
            mock_send_notifications.assert_called_once_with(mock_alert)

    def test_new_device_alert_minimal_info(self, alert_manager):
        """Test new device alert with minimal device information"""
        device_info = {
            "ip_address": "192.168.1.200",
            "last_seen": "2023-06-30 12:00:00",
        }

        with patch("src.alerts.manager.Alert") as mock_alert_class, patch.object(
            alert_manager, "_send_notifications"
        ):

            alert_manager.send_new_device_alert(device_info)

            create_call = mock_alert_class.call_args
            message = create_call[1]["message"]

            # Should handle missing optional fields gracefully
            assert "Unknown" in message  # For missing hostname, manufacturer, etc.
            assert device_info["ip_address"] in message


class TestExploitSuccessAlerts:
    """Test exploit success alert functionality"""

    def test_send_exploit_success_alert(self, alert_manager, sample_device):
        """Test sending exploit success alert"""
        exploit_info = {
            "vulnerability_name": "Buffer Overflow in SSH Service",
            "cve_id": "CVE-2023-9999",
            "exploit_type": "Remote Code Execution",
        }

        with patch("src.alerts.manager.Alert") as mock_alert_class, patch.object(
            alert_manager, "_send_notifications"
        ) as mock_send_notifications:

            mock_alert = Mock()
            mock_alert_class.return_value = mock_alert

            alert_manager.send_exploit_success_alert(sample_device, exploit_info)

            # Verify alert creation
            mock_alert_class.assert_called_once()
            create_call = mock_alert_class.call_args
            assert create_call[1]["severity"] == Severity.CRITICAL
            assert "EXPLOIT SUCCESSFUL" in create_call[1]["title"]
            assert "CRITICAL SECURITY BREACH" in create_call[1]["message"]
            assert exploit_info["vulnerability_name"] in create_call[1]["message"]
            assert create_call[1]["alert_metadata"]["requires_immediate_action"] == True

            # Verify database operations
            alert_manager.db.add.assert_called_once_with(mock_alert)
            alert_manager.db.commit.assert_called_once()

            # Verify notifications sent with force_all=True
            mock_send_notifications.assert_called_once_with(mock_alert, force_all=True)

    def test_exploit_success_alert_content(self, alert_manager, sample_device):
        """Test exploit success alert contains all required information"""
        exploit_info = {
            "vulnerability_name": "Critical RCE",
            "cve_id": "CVE-2023-1234",
            "exploit_type": "Remote",
        }

        with patch("src.alerts.manager.Alert") as mock_alert_class, patch.object(
            alert_manager, "_send_notifications"
        ):

            alert_manager.send_exploit_success_alert(sample_device, exploit_info)

            create_call = mock_alert_class.call_args
            message = create_call[1]["message"]

            # Verify message contains immediate action steps
            assert "IMMEDIATE ACTIONS REQUIRED" in message
            assert "Isolate the affected device" in message
            assert "Apply security patches" in message
            assert "Change all credentials" in message


class TestNotificationSystem:
    """Test notification sending system"""

    def test_send_notifications_critical_alert(self, alert_manager, sample_alert):
        """Test sending notifications for critical alert"""
        sample_alert.severity = Severity.CRITICAL

        with patch.object(
            alert_manager, "_send_email_notification"
        ) as mock_email, patch.object(
            alert_manager, "_send_slack_notification"
        ) as mock_slack:

            alert_manager._send_notifications(sample_alert)

            # Should send both email and Slack for critical alerts
            mock_email.assert_called_once_with(sample_alert)
            mock_slack.assert_called_once_with(sample_alert)

            # Should mark as sent
            assert sample_alert.notification_sent == True
            alert_manager.db.commit.assert_called()

    def test_send_notifications_info_alert_development(
        self, alert_manager, sample_alert
    ):
        """Test INFO alert notifications in development (should not send)"""
        sample_alert.severity = Severity.INFO
        alert_manager.settings.is_production = False

        with patch.object(
            alert_manager, "_send_email_notification"
        ) as mock_email, patch.object(
            alert_manager, "_send_slack_notification"
        ) as mock_slack:

            alert_manager._send_notifications(sample_alert)

            # Should not send notifications for INFO in development
            mock_email.assert_not_called()
            mock_slack.assert_not_called()

    def test_send_notifications_info_alert_production(
        self, alert_manager, sample_alert
    ):
        """Test INFO alert notifications in production"""
        sample_alert.severity = Severity.INFO
        alert_manager.settings.is_production = True

        with patch.object(
            alert_manager, "_send_email_notification"
        ) as mock_email, patch.object(
            alert_manager, "_send_slack_notification"
        ) as mock_slack:

            alert_manager._send_notifications(sample_alert)

            # Should send notifications for INFO in production
            mock_email.assert_called_once_with(sample_alert)
            mock_slack.assert_called_once_with(sample_alert)

    def test_send_notifications_force_all(self, alert_manager, sample_alert):
        """Test forced notification sending"""
        sample_alert.severity = Severity.LOW

        with patch.object(
            alert_manager, "_send_email_notification"
        ) as mock_email, patch.object(
            alert_manager, "_send_slack_notification"
        ) as mock_slack:

            alert_manager._send_notifications(sample_alert, force_all=True)

            # Should send all notifications when forced
            mock_email.assert_called_once_with(sample_alert)
            mock_slack.assert_called_once_with(sample_alert)

    def test_send_notifications_email_error(self, alert_manager, sample_alert):
        """Test notification sending with email error"""
        sample_alert.severity = Severity.CRITICAL

        with patch.object(
            alert_manager, "_send_email_notification"
        ) as mock_email, patch.object(
            alert_manager, "_send_slack_notification"
        ) as mock_slack:

            mock_email.side_effect = Exception("SMTP error")

            # Should not raise exception, continue with other notifications
            alert_manager._send_notifications(sample_alert)

            mock_email.assert_called_once()
            mock_slack.assert_called_once()  # Should still try Slack
            assert sample_alert.notification_sent == True  # Should still mark as sent

    def test_send_notifications_slack_error(self, alert_manager, sample_alert):
        """Test notification sending with Slack error"""
        sample_alert.severity = Severity.CRITICAL

        with patch.object(
            alert_manager, "_send_email_notification"
        ) as mock_email, patch.object(
            alert_manager, "_send_slack_notification"
        ) as mock_slack:

            mock_slack.side_effect = Exception("Slack API error")

            # Should not raise exception
            alert_manager._send_notifications(sample_alert)

            mock_email.assert_called_once()  # Should still try email
            mock_slack.assert_called_once()
            assert sample_alert.notification_sent == True


class TestEmailNotifications:
    """Test email notification functionality"""

    def test_send_email_notification_success(self, alert_manager, sample_alert):
        """Test successful email notification"""
        with patch("src.alerts.manager.smtplib.SMTP") as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp

            alert_manager._send_email_notification(sample_alert)

            # Verify SMTP connection
            mock_smtp_class.assert_called_once_with(
                alert_manager.settings.alert_email_smtp_host,
                alert_manager.settings.alert_email_smtp_port,
            )

            # Verify authentication
            mock_smtp.starttls.assert_called_once()
            mock_smtp.login.assert_called_once_with(
                alert_manager.settings.alert_email_username,
                alert_manager.settings.alert_email_password,
            )

            # Verify message sent
            mock_smtp.send_message.assert_called_once()

    def test_send_email_notification_no_auth(self, alert_manager, sample_alert):
        """Test email notification without authentication"""
        alert_manager.settings.alert_email_username = None
        alert_manager.settings.alert_email_password = None

        with patch("src.alerts.manager.smtplib.SMTP") as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp

            alert_manager._send_email_notification(sample_alert)

            # Should not attempt authentication
            mock_smtp.starttls.assert_not_called()
            mock_smtp.login.assert_not_called()

            # Should still send message
            mock_smtp.send_message.assert_called_once()

    def test_send_email_notification_incomplete_config(
        self, alert_manager, sample_alert
    ):
        """Test email notification with incomplete configuration"""
        alert_manager.settings.alert_email_smtp_host = None

        # Should not raise exception, just log warning
        alert_manager._send_email_notification(sample_alert)

        # No actual email sending should occur (covered by warning log)

    def test_email_message_format(self, alert_manager, sample_alert):
        """Test email message formatting"""
        sample_alert.severity = Severity.CRITICAL
        sample_alert.title = "Test Critical Alert"
        sample_alert.message = "This is a critical test message"

        with patch("src.alerts.manager.smtplib.SMTP") as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp

            alert_manager._send_email_notification(sample_alert)

            # Extract the message that was sent
            send_call = mock_smtp.send_message.call_args[0][0]

            # Verify subject contains severity and title
            assert "[Argus Alert - CRITICAL]" in send_call["Subject"]
            assert sample_alert.title in send_call["Subject"]

            # Verify recipients
            assert alert_manager.settings.alert_email_to[0] in send_call["To"]
            assert alert_manager.settings.alert_email_to[1] in send_call["To"]

    def test_email_severity_emojis(self, alert_manager, sample_alert):
        """Test email includes appropriate severity emojis"""
        severity_tests = [
            (Severity.CRITICAL, "🚨"),
            (Severity.HIGH, "⚠️"),
            (Severity.MEDIUM, "⚡"),
            (Severity.LOW, "ℹ️"),
            (Severity.INFO, "📌"),
        ]

        with patch("src.alerts.manager.smtplib.SMTP"):
            for severity, expected_emoji in severity_tests:
                sample_alert.severity = severity

                with patch("src.alerts.manager.MIMEText") as mock_mime_text:
                    alert_manager._send_email_notification(sample_alert)

                    # Check that emoji was included in the message body
                    body_call = mock_mime_text.call_args[0][0]
                    assert expected_emoji in body_call


class TestSlackNotifications:
    """Test Slack notification functionality"""

    @patch("src.alerts.manager.requests.post")
    def test_send_slack_notification_success(
        self, mock_post, alert_manager, sample_alert
    ):
        """Test successful Slack notification"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        alert_manager._send_slack_notification(sample_alert)

        # Verify Slack webhook called
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == alert_manager.settings.alert_slack_webhook
        assert call_args[1]["headers"]["Content-Type"] == "application/json"

        # Verify message structure
        slack_data = call_args[1]["json"]
        assert "attachments" in slack_data
        attachment = slack_data["attachments"][0]
        assert attachment["title"] == sample_alert.title
        assert attachment["text"] == sample_alert.message

    @patch("src.alerts.manager.requests.post")
    def test_send_slack_notification_colors(
        self, mock_post, alert_manager, sample_alert
    ):
        """Test Slack notification color coding by severity"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        color_tests = [
            (Severity.CRITICAL, "#FF0000"),
            (Severity.HIGH, "#FF8C00"),
            (Severity.MEDIUM, "#FFD700"),
            (Severity.LOW, "#1E90FF"),
            (Severity.INFO, "#808080"),
        ]

        for severity, expected_color in color_tests:
            sample_alert.severity = severity
            mock_post.reset_mock()

            alert_manager._send_slack_notification(sample_alert)

            slack_data = mock_post.call_args[1]["json"]
            assert slack_data["attachments"][0]["color"] == expected_color

    @patch("src.alerts.manager.requests.post")
    def test_send_slack_notification_critical_actions(
        self, mock_post, alert_manager, sample_alert
    ):
        """Test Slack notification includes action buttons for critical alerts"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        sample_alert.severity = Severity.CRITICAL
        sample_alert.id = 123

        alert_manager._send_slack_notification(sample_alert)

        slack_data = mock_post.call_args[1]["json"]
        attachment = slack_data["attachments"][0]

        # Should include action buttons for critical alerts
        assert "actions" in attachment
        actions = attachment["actions"]
        assert len(actions) == 2
        assert any("Dashboard" in action["text"] for action in actions)
        assert any("Acknowledge" in action["text"] for action in actions)

    @patch("src.alerts.manager.requests.post")
    def test_send_slack_notification_non_critical_no_actions(
        self, mock_post, alert_manager, sample_alert
    ):
        """Test Slack notification has no action buttons for non-critical alerts"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        sample_alert.severity = Severity.HIGH

        alert_manager._send_slack_notification(sample_alert)

        slack_data = mock_post.call_args[1]["json"]
        attachment = slack_data["attachments"][0]

        # Should not include action buttons for non-critical alerts
        assert "actions" not in attachment

    @patch("src.alerts.manager.requests.post")
    def test_send_slack_notification_api_error(
        self, mock_post, alert_manager, sample_alert
    ):
        """Test Slack notification API error handling"""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_post.return_value = mock_response

        with pytest.raises(Exception, match="Slack API returned 400"):
            alert_manager._send_slack_notification(sample_alert)

    def test_send_slack_notification_no_webhook(self, alert_manager, sample_alert):
        """Test Slack notification with no webhook configured"""
        alert_manager.settings.alert_slack_webhook = None

        # Should not raise exception, just log warning
        alert_manager._send_slack_notification(sample_alert)

        # No actual HTTP request should occur

    @patch("src.alerts.manager.requests.post")
    def test_slack_message_fields(self, mock_post, alert_manager, sample_alert):
        """Test Slack message includes proper fields"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        alert_manager._send_slack_notification(sample_alert)

        slack_data = mock_post.call_args[1]["json"]
        attachment = slack_data["attachments"][0]
        fields = attachment["fields"]

        # Should include severity and time fields
        field_titles = [field["title"] for field in fields]
        assert "Severity" in field_titles
        assert "Time" in field_titles

        # Verify footer and timestamp
        assert attachment["footer"] == "Argus Network Scanner"
        assert "ts" in attachment


class TestAlertAcknowledgment:
    """Test alert acknowledgment functionality"""

    def test_acknowledge_alert_success(self, alert_manager):
        """Test successful alert acknowledgment"""
        mock_alert = Mock()
        mock_alert.acknowledged = False
        alert_manager.db.query().filter_by().first.return_value = mock_alert

        alert_manager.acknowledge_alert(123, "admin@example.com")

        # Verify alert was acknowledged
        assert mock_alert.acknowledged == True
        assert mock_alert.acknowledged_by == "admin@example.com"
        assert mock_alert.acknowledged_at is not None
        alert_manager.db.commit.assert_called_once()

    def test_acknowledge_alert_default_user(self, alert_manager):
        """Test alert acknowledgment with default user"""
        mock_alert = Mock()
        alert_manager.db.query().filter_by().first.return_value = mock_alert

        alert_manager.acknowledge_alert(123)

        # Should use default "system" user
        assert mock_alert.acknowledged_by == "system"

    def test_acknowledge_alert_not_found(self, alert_manager):
        """Test acknowledgment of non-existent alert"""
        alert_manager.db.query().filter_by().first.return_value = None

        # Should not raise exception
        alert_manager.acknowledge_alert(999)

        # Should not commit anything
        alert_manager.db.commit.assert_not_called()


class TestConfigurationValidation:
    """Test configuration validation and error handling"""

    def test_email_disabled(self, alert_manager, sample_alert):
        """Test behavior when email notifications are disabled"""
        alert_manager.settings.alert_email_enabled = False

        with patch.object(
            alert_manager, "_send_email_notification"
        ) as mock_email, patch.object(
            alert_manager, "_send_slack_notification"
        ) as mock_slack:

            alert_manager._send_notifications(sample_alert)

            # Should not send email when disabled
            mock_email.assert_not_called()
            mock_slack.assert_called_once()  # Slack should still work

    def test_slack_disabled(self, alert_manager, sample_alert):
        """Test behavior when Slack notifications are disabled"""
        alert_manager.settings.alert_slack_enabled = False

        with patch.object(
            alert_manager, "_send_email_notification"
        ) as mock_email, patch.object(
            alert_manager, "_send_slack_notification"
        ) as mock_slack:

            alert_manager._send_notifications(sample_alert)

            # Should not send Slack when disabled
            mock_slack.assert_not_called()
            mock_email.assert_called_once()  # Email should still work

    def test_all_notifications_disabled(self, alert_manager, sample_alert):
        """Test behavior when all notifications are disabled"""
        alert_manager.settings.alert_email_enabled = False
        alert_manager.settings.alert_slack_enabled = False

        with patch.object(
            alert_manager, "_send_email_notification"
        ) as mock_email, patch.object(
            alert_manager, "_send_slack_notification"
        ) as mock_slack:

            alert_manager._send_notifications(sample_alert)

            # Should not send any notifications
            mock_email.assert_not_called()
            mock_slack.assert_not_called()

            # Should still mark as sent (even if no actual notifications)
            assert sample_alert.notification_sent == True


class TestSeverityClassification:
    """Test alert severity classification and behavior"""

    def test_severity_notification_thresholds(self, alert_manager):
        """Test which severities trigger notifications"""
        test_cases = [
            (Severity.CRITICAL, True),
            (Severity.HIGH, True),
            (Severity.MEDIUM, False),
            (Severity.LOW, False),
            (Severity.INFO, False),
        ]

        for severity, should_notify in test_cases:
            sample_alert = Mock()
            sample_alert.severity = severity

            with patch.object(
                alert_manager, "_send_email_notification"
            ) as mock_email, patch.object(
                alert_manager, "_send_slack_notification"
            ) as mock_slack:

                alert_manager._send_notifications(sample_alert)

                if should_notify:
                    mock_email.assert_called_once()
                    mock_slack.assert_called_once()
                else:
                    mock_email.assert_not_called()
                    mock_slack.assert_not_called()

    def test_production_info_notifications(self, alert_manager):
        """Test INFO notifications in production environment"""
        alert_manager.settings.is_production = True

        sample_alert = Mock()
        sample_alert.severity = Severity.INFO

        with patch.object(
            alert_manager, "_send_email_notification"
        ) as mock_email, patch.object(
            alert_manager, "_send_slack_notification"
        ) as mock_slack:

            alert_manager._send_notifications(sample_alert)

            # Should send notifications for INFO in production
            mock_email.assert_called_once()
            mock_slack.assert_called_once()


@pytest.mark.integration
class TestIntegrationScenarios:
    """Integration tests for realistic alert scenarios"""

    def test_full_critical_vulnerability_workflow(
        self, alert_manager, sample_device, sample_vulnerabilities
    ):
        """Test complete critical vulnerability alert workflow"""
        with patch("src.alerts.manager.Alert") as mock_alert_class, patch.object(
            alert_manager, "_send_email_notification"
        ) as mock_email, patch.object(
            alert_manager, "_send_slack_notification"
        ) as mock_slack:

            mock_alert = Mock()
            mock_alert.severity = Severity.CRITICAL
            mock_alert_class.return_value = mock_alert

            # Send alert
            alert_manager.send_critical_vulnerability_alert(
                sample_device, sample_vulnerabilities
            )

            # Verify complete workflow
            # 1. Alert created in database
            alert_manager.db.add.assert_called_once_with(mock_alert)
            alert_manager.db.commit.assert_called()

            # 2. Notifications sent
            mock_email.assert_called_once_with(mock_alert)
            mock_slack.assert_called_once_with(mock_alert)

            # 3. Alert marked as sent
            assert mock_alert.notification_sent == True

    def test_notification_failure_resilience(
        self, alert_manager, sample_device, sample_vulnerabilities
    ):
        """Test system resilience when notifications fail"""
        # Ensure notifications are enabled for this test
        alert_manager.settings.alert_email_enabled = True
        alert_manager.settings.alert_slack_enabled = True

        with patch("src.alerts.manager.Alert") as mock_alert_class:

            mock_alert = Mock()
            mock_alert.notification_sent = False  # Initialize to False
            mock_alert.severity = (
                Severity.CRITICAL
            )  # Ensure it's critical so notifications are sent
            mock_alert_class.return_value = mock_alert

            # Mock the notification methods to fail
            with patch.object(
                alert_manager, "_send_email_notification"
            ) as mock_email, patch.object(
                alert_manager, "_send_slack_notification"
            ) as mock_slack:

                mock_email.side_effect = Exception("Email server down")
                mock_slack.side_effect = Exception("Slack API error")

                # Should not raise exception - this is the key test
                alert_manager.send_critical_vulnerability_alert(
                    sample_device, sample_vulnerabilities
                )

                # Alert should still be created (system resilience)
                alert_manager.db.add.assert_called_once()
                alert_manager.db.commit.assert_called()

                # Both notification methods should have been attempted despite failures
                mock_email.assert_called_once()
                mock_slack.assert_called_once()

                # Notification status should be marked as sent even if individual methods failed
                # (this shows the system continues to function)
                assert mock_alert.notification_sent == True

    def test_multiple_alert_types_workflow(self, alert_manager, sample_device):
        """Test handling multiple types of alerts in sequence"""
        with patch("src.alerts.manager.Alert") as mock_alert_class, patch.object(
            alert_manager, "_send_notifications"
        ) as mock_send_notifications:

            mock_alert = Mock()
            mock_alert_class.return_value = mock_alert

            # Send different types of alerts
            alert_manager.send_critical_vulnerability_alert(sample_device, [])
            alert_manager.send_new_device_alert(
                {"ip_address": "192.168.1.200", "last_seen": "2023-06-30 12:00:00"}
            )
            alert_manager.send_exploit_success_alert(
                sample_device, {"vulnerability_name": "Test"}
            )

            # All should be processed
            assert mock_alert_class.call_count == 3
            assert alert_manager.db.add.call_count == 3
            assert alert_manager.db.commit.call_count == 3
