import logging
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sys
import platform
import threading

logger = logging.getLogger(__name__)

class NotificationManager:
    def __init__(self, config):
        self.config = config

    def send_email(self, subject, body):
        try:
            server = self.config.get("email_server", "smtp.gmail.com")
            port = int(self.config.get("email_port", 587))
            user = self.config.get("email_user", "")
            password = self.config.get("email_password", "")
            recipient = self.config.get("email_recipient", "")
            
            if not user or not password or not recipient:
                logger.warning("Email settings not configured")
                return False

            msg = MIMEMultipart()
            msg['From'] = user
            msg['To'] = recipient
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(server, port) as server:
                server.starttls()
                server.login(user, password)
                text = msg.as_string()
                server.sendmail(user, recipient, text)
            logger.info("Email sent successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

    def send_discord_webhook(self, message):
        try:
            webhook_url = self.config.get("discord_webhook", "")
            if not webhook_url:
                logger.warning("Discord webhook not configured")
                return False
            
            data = {"content": message}
            response = requests.post(webhook_url, json=data)
            response.raise_for_status()
            logger.info("Discord notification sent")
            return True
        except Exception as e:
            logger.error(f"Failed to send Discord webhook: {e}")
            return False

    def send_slack_webhook(self, message):
        try:
            webhook_url = self.config.get("slack_webhook", "")
            if not webhook_url:
                logger.warning("Slack webhook not configured")
                return False
            
            data = {"text": message}
            response = requests.post(webhook_url, json=data)
            response.raise_for_status()
            logger.info("Slack notification sent")
            return True
        except Exception as e:
            logger.error(f"Failed to send Slack webhook: {e}")
            return False

    def send_system_toast(self, title, message):
        try:
            if platform.system() == "Windows":
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast(title, message, duration=10)
            elif platform.system() == "Darwin":  # macOS
                import subprocess
                script = f'display notification "{message}" with title "{title}"'
                subprocess.run(["osascript", "-e", script])
            elif platform.system() == "Linux":
                try:
                    import subprocess
                    subprocess.run(["notify-send", title, message])
                except Exception:
                    logger.warning("notify-send not found on Linux")
            logger.info("System toast sent")
            return True
        except Exception as e:
            logger.error(f"Failed to send system toast: {e}")
            return False

    def send_all(self, subject, body, use_email=False, use_discord=False, use_slack=False, use_toast=False):
        threading.Thread(target=self._send_all_threaded, args=(subject, body, use_email, use_discord, use_slack, use_toast)).start()

    def _send_all_threaded(self, subject, body, use_email, use_discord, use_slack, use_toast):
        if use_email:
            self.send_email(subject, body)
        if use_discord:
            self.send_discord_webhook(f"{subject}\n{body}")
        if use_slack:
            self.send_slack_webhook(f"{subject}\n{body}")
        if use_toast:
            self.send_system_toast(subject, body)
