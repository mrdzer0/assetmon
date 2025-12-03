"""
Telegram notification implementation
"""

import logging
from typing import List, Dict, Any
import requests
from app.services.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class TelegramNotifier(BaseNotifier):
    """Telegram bot notifier"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.bot_token = config.get("bot_token")
        self.chat_id = config.get("chat_id")
        self.min_severity = config.get("min_severity", "info")

        if not self.bot_token or not self.chat_id:
            self.enabled = False
            logger.warning("Telegram bot token or chat ID not configured")

    def send(self, events: List[Dict[str, Any]], project_name: str = None, scan_mode: str = None) -> bool:
        """Send Telegram notification"""
        if not self.enabled or not self.bot_token or not self.chat_id:
            return False

        # Filter events by severity
        filtered_events = self.filter_events_by_severity(events, self.min_severity)

        if not filtered_events:
            logger.info("No events to notify after severity filtering")
            return True

        # Build message
        message = self._build_telegram_message(filtered_events, project_name, scan_mode)

        # Telegram API endpoint
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

        payload = {
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }

        try:
            response = requests.post(url, json=payload, timeout=10)

            if response.status_code == 200:
                logger.info(f"Telegram notification sent: {len(filtered_events)} events")
                return True
            else:
                logger.error(f"Telegram notification failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Telegram notification error: {e}")
            return False

    def _build_telegram_message(
        self,
        events: List[Dict],
        project_name: str,
        scan_mode: str
    ) -> str:
        """Build Telegram message with Markdown formatting"""

        lines = []

        # Header
        lines.append("🔍 *Asset Monitor Alert*")
        lines.append("")

        if project_name:
            lines.append(f"*Project:* {project_name}")
        if scan_mode:
            lines.append(f"*Scan Mode:* {scan_mode}")

        lines.append(f"*Events:* {len(events)}")
        lines.append("")

        # Count by severity
        severity_counts = {}
        for event in events:
            sev = str(event.get("severity", "info")).lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append("*Summary:*")
        for sev, count in sorted(severity_counts.items(), key=lambda x: x[0]):
            emoji = self._get_severity_emoji(sev)
            lines.append(f"{emoji} {sev.upper()}: {count}")

        lines.append("")
        lines.append("───────────────")
        lines.append("")

        # Events (limit to 10)
        for i, event in enumerate(events[:10], 1):
            severity = str(event.get("severity", "info")).lower()
            emoji = self._get_severity_emoji(severity)

            event_type = str(event.get("type", "unknown"))
            summary = event.get("summary", "No summary")

            lines.append(f"{i}. {emoji} *{severity.upper()}* - {event_type}")
            lines.append(f"   {summary}")
            lines.append("")

        if len(events) > 10:
            lines.append(f"_... and {len(events) - 10} more events_")

        lines.append("───────────────")
        lines.append("_Asset Monitor_")

        message = "\n".join(lines)

        # Telegram message limit is 4096 characters
        if len(message) > 4000:
            message = message[:3997] + "..."

        return message

    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪"
        }
        return emojis.get(severity.lower(), "⚪")
