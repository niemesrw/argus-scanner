"""
Alert management system for critical security events
"""

import logging
from typing import List, Dict, Optional
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import requests

from src.config.settings import Settings
from src.database.models import Alert, Severity, Device, get_db_session

logger = logging.getLogger(__name__)


class AlertManager:
    """Manages security alerts and notifications"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.db = get_db_session(settings.db_path)

    def send_critical_vulnerability_alert(
        self, device: Device, vulnerabilities: List[Dict]
    ):
        """Send alert for critical vulnerabilities"""
        title = (
            f"Critical Vulnerabilities Found on {device.hostname or device.ip_address}"
        )

        # Build message
        message_parts = [
            f"Device: {device.hostname or device.ip_address} ({device.ip_address})",
            f"MAC Address: {device.mac_address}",
            f"Risk Score: {device.risk_score}",
            "",
            "Critical Vulnerabilities:",
        ]

        for vuln in vulnerabilities:
            message_parts.extend(
                [
                    f"- {vuln['name']}",
                    f"  CVE: {vuln.get('cve_id', 'N/A')}",
                    f"  Description: {vuln['description'][:200]}...",
                ]
            )

        message = "\n".join(message_parts)

        # Create alert record
        alert = Alert(
            severity=Severity.CRITICAL,
            title=title,
            message=message,
            alert_metadata={
                "device_id": device.id,
                "vulnerability_count": len(vulnerabilities),
                "cve_ids": [
                    v.get("cve_id") for v in vulnerabilities if v.get("cve_id")
                ],
            },
        )
        self.db.add(alert)
        self.db.commit()

        # Send notifications
        self._send_notifications(alert)

    def send_new_device_alert(self, device_info: Dict):
        """Send alert for newly discovered device"""
        title = f"New Device Discovered: {device_info.get('hostname', device_info['ip_address'])}"

        message_parts = [
            f"IP Address: {device_info['ip_address']}",
            f"MAC Address: {device_info.get('mac_address', 'Unknown')}",
            f"Hostname: {device_info.get('hostname', 'Unknown')}",
            f"Manufacturer: {device_info.get('manufacturer', 'Unknown')}",
            f"First Seen: {device_info['last_seen']}",
        ]

        message = "\n".join(message_parts)

        # Create alert record
        alert = Alert(
            severity=Severity.INFO,
            title=title,
            message=message,
            alert_metadata=device_info,
        )
        self.db.add(alert)
        self.db.commit()

        # Send notifications for new devices if configured
        if self.settings.environment == "production":
            self._send_notifications(alert)

    def send_exploit_success_alert(self, device: Device, exploit_info: Dict):
        """Send high-priority alert for successful exploit"""
        title = f"EXPLOIT SUCCESSFUL - IMMEDIATE ACTION REQUIRED"

        message_parts = [
            "⚠️  CRITICAL SECURITY BREACH DETECTED ⚠️",
            "",
            f"Device: {device.hostname or device.ip_address} ({device.ip_address})",
            f"Vulnerability: {exploit_info.get('vulnerability_name')}",
            f"CVE: {exploit_info.get('cve_id', 'N/A')}",
            f"Exploit Type: {exploit_info.get('exploit_type')}",
            "",
            "IMMEDIATE ACTIONS REQUIRED:",
            "1. Isolate the affected device from the network",
            "2. Review security logs for compromise indicators",
            "3. Apply security patches immediately",
            "4. Change all credentials on the affected system",
            "",
            f"Time of Exploit: {datetime.utcnow()}",
        ]

        message = "\n".join(message_parts)

        # Create critical alert
        alert = Alert(
            severity=Severity.CRITICAL,
            title=title,
            message=message,
            alert_metadata={
                "device_id": device.id,
                "exploit_info": exploit_info,
                "requires_immediate_action": True,
            },
        )
        self.db.add(alert)
        self.db.commit()

        # Send all available notifications for critical exploits
        self._send_notifications(alert, force_all=True)

    def _send_notifications(self, alert: Alert, force_all: bool = False):
        """Send notifications through configured channels"""
        # Only send notifications for high/critical alerts unless forced
        if not force_all and alert.severity not in [Severity.HIGH, Severity.CRITICAL]:
            if alert.severity != Severity.INFO or not self._should_notify_info():
                return

        # Email notification
        if self.settings.alert_email_enabled:
            try:
                self._send_email_notification(alert)
                logger.info(f"Email notification sent for alert {alert.id}")
            except Exception as e:
                logger.error(f"Failed to send email notification: {e}")

        # Slack notification
        if self.settings.alert_slack_enabled:
            try:
                self._send_slack_notification(alert)
                logger.info(f"Slack notification sent for alert {alert.id}")
            except Exception as e:
                logger.error(f"Failed to send Slack notification: {e}")

        # Update notification status
        alert.notification_sent = True
        self.db.commit()

    def _send_email_notification(self, alert: Alert):
        """Send email notification"""
        if not all(
            [
                self.settings.alert_email_smtp_host,
                self.settings.alert_email_from,
                self.settings.alert_email_to,
            ]
        ):
            logger.warning(
                "Email configuration incomplete, skipping email notification"
            )
            return

        # Create message
        msg = MIMEMultipart()
        msg["From"] = self.settings.alert_email_from
        msg["To"] = ", ".join(self.settings.alert_email_to)
        msg["Subject"] = f"[Argus Alert - {alert.severity.value.upper()}] {alert.title}"

        # Add severity indicator to body
        severity_emoji = {
            Severity.CRITICAL: "🚨",
            Severity.HIGH: "⚠️",
            Severity.MEDIUM: "⚡",
            Severity.LOW: "ℹ️",
            Severity.INFO: "📌",
        }

        body = (
            f"{severity_emoji.get(alert.severity, '')} {alert.title}\n\n{alert.message}"
        )
        msg.attach(MIMEText(body, "plain"))

        # Send email
        with smtplib.SMTP(
            self.settings.alert_email_smtp_host, self.settings.alert_email_smtp_port
        ) as server:
            if (
                self.settings.alert_email_username
                and self.settings.alert_email_password
            ):
                server.starttls()
                server.login(
                    self.settings.alert_email_username,
                    self.settings.alert_email_password,
                )

            server.send_message(msg)

    def _send_slack_notification(self, alert: Alert):
        """Send Slack notification via webhook"""
        if not self.settings.alert_slack_webhook:
            logger.warning("Slack webhook not configured, skipping Slack notification")
            return

        # Color coding for severity
        color_map = {
            Severity.CRITICAL: "#FF0000",  # Red
            Severity.HIGH: "#FF8C00",  # Dark Orange
            Severity.MEDIUM: "#FFD700",  # Gold
            Severity.LOW: "#1E90FF",  # Dodger Blue
            Severity.INFO: "#808080",  # Gray
        }

        # Build Slack message
        slack_data = {
            "attachments": [
                {
                    "color": color_map.get(alert.severity, "#808080"),
                    "title": alert.title,
                    "text": alert.message,
                    "fields": [
                        {
                            "title": "Severity",
                            "value": alert.severity.value.upper(),
                            "short": True,
                        },
                        {
                            "title": "Time",
                            "value": alert.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                            "short": True,
                        },
                    ],
                    "footer": "Argus Network Scanner",
                    "ts": int(alert.created_at.timestamp()),
                }
            ]
        }

        # Add action buttons for critical alerts
        if alert.severity == Severity.CRITICAL:
            slack_data["attachments"][0]["actions"] = [
                {
                    "type": "button",
                    "text": "View Dashboard",
                    "url": f"http://{self.settings.network_range.split('/')[0]}:{self.settings.web_port}",
                },
                {
                    "type": "button",
                    "text": "Acknowledge",
                    "url": f"http://{self.settings.network_range.split('/')[0]}:{self.settings.web_port}/alerts/{alert.id}/acknowledge",
                },
            ]

        # Send to Slack
        response = requests.post(
            self.settings.alert_slack_webhook,
            json=slack_data,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code != 200:
            raise Exception(
                f"Slack API returned {response.status_code}: {response.text}"
            )

    def _should_notify_info(self) -> bool:
        """Determine if INFO level alerts should trigger notifications"""
        # In development, don't send INFO notifications
        return self.settings.is_production

    def acknowledge_alert(self, alert_id: int, acknowledged_by: str = "system"):
        """Mark an alert as acknowledged"""
        alert = self.db.query(Alert).filter_by(id=alert_id).first()
        if alert:
            alert.acknowledged = True
            alert.acknowledged_at = datetime.utcnow()
            alert.acknowledged_by = acknowledged_by
            self.db.commit()
            logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
