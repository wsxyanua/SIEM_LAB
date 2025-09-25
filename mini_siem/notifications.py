import json
import smtplib
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional

import requests

from .config import load_config
from .logger import logger


class NotificationManager:
    """Manages notifications for security events"""
    
    def __init__(self):
        self.cfg = load_config()
        self.last_notification_time: Dict[str, float] = {}
        self.rate_limit_seconds = 300  # 5 minutes between same type notifications
    
    def _should_send_notification(self, notification_type: str) -> bool:
        """Check if notification should be sent based on rate limiting"""
        now = time.time()
        last_time = self.last_notification_time.get(notification_type, 0)
        
        if now - last_time < self.rate_limit_seconds:
            return False
        
        self.last_notification_time[notification_type] = now
        return True
    
    def _get_config_value(self, key: str, default=None):
        """Get configuration value with fallback"""
        # This would be extended to read from config file
        # For now, using environment variables
        import os
        return os.environ.get(f"SIEM_{key.upper()}", default)
    
    def send_email(self, subject: str, body: str, to_emails: Optional[List[str]] = None) -> bool:
        """Send email notification"""
        try:
            smtp_server = self._get_config_value("smtp_server", "localhost")
            smtp_port = int(self._get_config_value("smtp_port", "587"))
            smtp_user = self._get_config_value("smtp_user")
            smtp_password = self._get_config_value("smtp_password")
            from_email = self._get_config_value("from_email", "siem@localhost")
            
            if not to_emails:
                to_emails = self._get_config_value("notification_emails", "").split(",")
                to_emails = [email.strip() for email in to_emails if email.strip()]
            
            if not to_emails:
                logger.warning("No email recipients configured")
                return False
            
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = ", ".join(to_emails)
            msg['Subject'] = f"[SIEM Alert] {subject}"
            
            msg.attach(MIMEText(body, 'html'))
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if smtp_user and smtp_password:
                    server.starttls()
                    server.login(smtp_user, smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email notification sent to {len(to_emails)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False
    
    def send_slack(self, message: str, webhook_url: Optional[str] = None) -> bool:
        """Send Slack notification"""
        try:
            if not webhook_url:
                webhook_url = self._get_config_value("slack_webhook")
            
            if not webhook_url:
                logger.warning("No Slack webhook configured")
                return False
            
            payload = {
                "text": message,
                "username": "SIEM Bot",
                "icon_emoji": ":shield:",
                "channel": self._get_config_value("slack_channel", "#security")
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info("Slack notification sent successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False
    
    def notify_brute_force_detected(self, ip: str, attempts: int, usernames: List[str], geo_info: Optional[Dict] = None) -> None:
        """Send notification for brute force detection"""
        if not self._should_send_notification(f"brute_force_{ip}"):
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        location_info = ""
        if geo_info:
            location_info = f"<br><strong>Location:</strong> {geo_info.get('city', 'Unknown')}, {geo_info.get('country', 'Unknown')}"
        
        subject = f"SSH Brute Force Detected from {ip}"
        body = f"""
        <html>
        <body>
            <h2>🚨 Security Alert: SSH Brute Force Attack Detected</h2>
            
            <p><strong>Time:</strong> {timestamp}</p>
            <p><strong>Source IP:</strong> {ip}</p>
            <p><strong>Attempts:</strong> {attempts}</p>
            <p><strong>Targeted Users:</strong> {', '.join(usernames[:5])}{'...' if len(usernames) > 5 else ''}</p>
            {location_info}
            
            <p><strong>Action Taken:</strong> IP has been automatically blocked</p>
            
            <p>You can view more details in the SIEM dashboard or check the logs.</p>
        </body>
        </html>
        """
        
        slack_message = f"""
🚨 *SSH Brute Force Attack Detected*
• *IP:* {ip}
• *Attempts:* {attempts}
• *Time:* {timestamp}
• *Users:* {', '.join(usernames[:3])}{'...' if len(usernames) > 3 else ''}
• *Action:* IP blocked automatically
        """
        
        # Send both email and Slack
        self.send_email(subject, body)
        self.send_slack(slack_message)
    
    def notify_ip_blocked(self, ip: str, reason: str, duration: int, geo_info: Optional[Dict] = None) -> None:
        """Send notification for IP blocking"""
        if not self._should_send_notification(f"block_{ip}"):
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        location_info = ""
        if geo_info:
            location_info = f"<br><strong>Location:</strong> {geo_info.get('city', 'Unknown')}, {geo_info.get('country', 'Unknown')}"
        
        subject = f"IP {ip} Blocked by SIEM"
        body = f"""
        <html>
        <body>
            <h2>🛡️ IP Address Blocked</h2>
            
            <p><strong>Time:</strong> {timestamp}</p>
            <p><strong>Blocked IP:</strong> {ip}</p>
            <p><strong>Reason:</strong> {reason}</p>
            <p><strong>Duration:</strong> {duration} seconds</p>
            {location_info}
            
            <p>This IP has been automatically added to the firewall blacklist.</p>
        </body>
        </html>
        """
        
        slack_message = f"""
🛡️ *IP Blocked*
• *IP:* {ip}
• *Reason:* {reason}
• *Duration:* {duration}s
• *Time:* {timestamp}
        """
        
        self.send_email(subject, body)
        self.send_slack(slack_message)
    
    def notify_system_status(self, status: str, details: str) -> None:
        """Send system status notification"""
        if not self._should_send_notification("system_status"):
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        subject = f"SIEM System Status: {status}"
        body = f"""
        <html>
        <body>
            <h2>📊 SIEM System Status Update</h2>
            
            <p><strong>Time:</strong> {timestamp}</p>
            <p><strong>Status:</strong> {status}</p>
            <p><strong>Details:</strong> {details}</p>
        </body>
        </html>
        """
        
        slack_message = f"""
📊 *SIEM System Status*
• *Status:* {status}
• *Details:* {details}
• *Time:* {timestamp}
        """
        
        self.send_email(subject, body)
        self.send_slack(slack_message)


# Global notification manager instance
notification_manager = NotificationManager()
