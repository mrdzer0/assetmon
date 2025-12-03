"""
Discord notification implementation
"""

import logging
from typing import List, Dict, Any
import requests
from app.services.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class DiscordNotifier(BaseNotifier):
    """Discord webhook notifier"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url")
        self.min_severity = config.get("min_severity", "info")

        if not self.webhook_url:
            self.enabled = False
            logger.warning("Discord webhook URL not configured")

    def send(self, events: List[Dict[str, Any]], project_name: str = None, scan_mode: str = None) -> bool:
        """Send Discord notification"""
        if not self.enabled or not self.webhook_url:
            return False

        # Filter events by severity
        filtered_events = self.filter_events_by_severity(events, self.min_severity)

        if not filtered_events:
            logger.info("No events to notify after severity filtering")
            return True

        # Build Discord embed
        embed = self._build_discord_embed(filtered_events, project_name, scan_mode)

        payload = {
            "embeds": [embed]
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )

            if response.status_code in [200, 204]:
                logger.info(f"Discord notification sent: {len(filtered_events)} events")
                return True
            else:
                logger.error(f"Discord notification failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Discord notification error: {e}")
            return False

    def _build_discord_embed(
        self,
        events: List[Dict],
        project_name: str,
        scan_mode: str
    ) -> Dict:
        """Build Discord embed"""

        # Title
        title = f"🔍 Asset Monitor: {project_name or 'Scan'}"
        if scan_mode:
            title += f" ({scan_mode} scan)"

        # Count by severity
        severity_counts = {}
        for event in events:
            sev = str(event.get("severity", "info")).lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Description
        description = f"**{len(events)} events detected**\n\n"
        for sev, count in sorted(severity_counts.items(), key=lambda x: x[0]):
            emoji = self._get_severity_emoji(sev)
            description += f"{emoji} {sev.upper()}: {count}  "

        # Fields for events (limit to 10)
        fields = []
        for event in events[:10]:
            severity = str(event.get("severity", "info")).lower()
            emoji = self._get_severity_emoji(severity)

            event_type = str(event.get("type", "unknown"))
            summary = event.get("summary", "No summary")

            name = f"{emoji} {severity.upper()} - {event_type}"
            value = summary[:1024]  # Discord field value limit

            fields.append({
                "name": name,
                "value": value,
                "inline": False
            })

        if len(events) > 10:
            fields.append({
                "name": "More events",
                "value": f"... and {len(events) - 10} more events",
                "inline": False
            })

        # Color based on highest severity
        color = self._get_severity_color(max(
            str(event.get("severity", "info")).lower()
            for event in events
        ))

        embed = {
            "title": title,
            "description": description,
            "color": color,
            "fields": fields,
            "footer": {
                "text": "Asset Monitor"
            }
        }

        return embed

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

    def _get_severity_color(self, severity: str) -> int:
        """Get Discord color for severity (decimal)"""
        colors = {
            "critical": 0xFF0000,  # Red
            "high": 0xFF6600,      # Orange
            "medium": 0xFFCC00,    # Yellow
            "low": 0x0099FF,       # Blue
            "info": 0x999999       # Gray
        }
        return colors.get(severity.lower(), 0x999999)
