"""
Slack notification implementation
"""

import logging
from typing import List, Dict, Any
import requests
from app.services.notifiers.base import BaseNotifier

logger = logging.getLogger(__name__)


class SlackNotifier(BaseNotifier):
    """Slack webhook notifier"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url")
        self.min_severity = config.get("min_severity", "info")

        if not self.webhook_url:
            self.enabled = False
            logger.warning("Slack webhook URL not configured")

    def send(self, events: List[Dict[str, Any]], project_name: str = None, scan_mode: str = None) -> bool:
        """Send Slack notification"""
        if not self.enabled or not self.webhook_url:
            return False

        # Filter events by severity
        filtered_events = self.filter_events_by_severity(events, self.min_severity)

        if not filtered_events:
            logger.info("No events to notify after severity filtering")
            return True

        # Build Slack message
        blocks = self._build_slack_blocks(filtered_events, project_name, scan_mode)

        payload = {
            "blocks": blocks
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"Slack notification sent: {len(filtered_events)} events")
                return True
            else:
                logger.error(f"Slack notification failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Slack notification error: {e}")
            return False

    def _build_slack_blocks(
        self,
        events: List[Dict],
        project_name: str,
        scan_mode: str
    ) -> List[Dict]:
        """Build Slack message blocks"""

        blocks = []

        # Header
        header_text = f"🔍 Asset Monitor: {project_name or 'Scan'}"
        if scan_mode:
            header_text += f" ({scan_mode} scan)"

        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": header_text
            }
        })

        # Summary
        summary_text = f"*{len(events)} events detected*\n"

        # Count by severity
        severity_counts = {}
        for event in events:
            sev = str(event.get("severity", "info")).lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for sev, count in sorted(severity_counts.items(), key=lambda x: x[0]):
            emoji = self._get_severity_emoji(sev)
            summary_text += f"{emoji} {sev.upper()}: {count}  "

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": summary_text
            }
        })

        # Divider
        blocks.append({"type": "divider"})

        # Events (limit to 10 for readability)
        for event in events[:10]:
            severity = str(event.get("severity", "info")).lower()
            emoji = self._get_severity_emoji(severity)

            event_type = str(event.get("type", "unknown"))
            summary = event.get("summary", "No summary")

            text = f"{emoji} *{severity.upper()}* - {event_type}\n{summary}"

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": text
                }
            })

        # Show more message if truncated
        if len(events) > 10:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"_... and {len(events) - 10} more events_"
                }]
            })

        return blocks

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
