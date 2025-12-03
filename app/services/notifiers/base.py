"""
Base notifier class and notification system
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class BaseNotifier(ABC):
    """Abstract base class for notification channels"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize notifier with configuration

        Args:
            config: Notifier-specific configuration
        """
        self.config = config
        self.enabled = config.get("enabled", True)

    @abstractmethod
    def send(self, events: List[Dict[str, Any]], project_name: str = None, scan_mode: str = None) -> bool:
        """
        Send notification with events

        Args:
            events: List of events to notify about
            project_name: Name of the project
            scan_mode: Scan mode (normal/weekly)

        Returns:
            True if notification sent successfully
        """
        pass

    def filter_events_by_severity(self, events: List[Dict], min_severity: str) -> List[Dict]:
        """
        Filter events by minimum severity level

        Args:
            events: List of events
            min_severity: Minimum severity (info, low, medium, high, critical)

        Returns:
            Filtered events
        """
        severity_order = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }

        min_level = severity_order.get(min_severity.lower(), 0)

        filtered = []
        for event in events:
            event_severity = event.get("severity", "info")
            if isinstance(event_severity, str):
                event_level = severity_order.get(event_severity.lower(), 0)
            else:
                # Handle Enum
                event_level = severity_order.get(str(event_severity.value).lower(), 0)

            if event_level >= min_level:
                filtered.append(event)

        return filtered

    def format_event_summary(self, event: Dict) -> str:
        """
        Format event for display

        Args:
            event: Event dict

        Returns:
            Formatted string
        """
        severity = event.get("severity", "info")
        if not isinstance(severity, str):
            severity = severity.value

        event_type = event.get("type", "unknown")
        if not isinstance(event_type, str):
            event_type = event_type.value

        summary = event.get("summary", "No summary")

        return f"[{severity.upper()}] {event_type}: {summary}"


class NotificationManager:
    """Manages multiple notification channels"""

    def __init__(self):
        self.notifiers: List[BaseNotifier] = []

    def add_notifier(self, notifier: BaseNotifier):
        """Add a notifier to the manager"""
        if notifier.enabled:
            self.notifiers.append(notifier)
            logger.info(f"Added notifier: {notifier.__class__.__name__}")

    def send_notifications(
        self,
        events: List[Dict],
        project_name: str = None,
        scan_mode: str = None
    ) -> Dict[str, bool]:
        """
        Send notifications to all registered channels

        Args:
            events: List of events
            project_name: Project name
            scan_mode: Scan mode

        Returns:
            Dict of notifier name -> success status
        """
        if not events:
            logger.info("No events to notify about")
            return {}

        results = {}

        for notifier in self.notifiers:
            notifier_name = notifier.__class__.__name__

            try:
                success = notifier.send(events, project_name, scan_mode)
                results[notifier_name] = success

                if success:
                    logger.info(f"Notification sent via {notifier_name}")
                else:
                    logger.warning(f"Notification failed via {notifier_name}")

            except Exception as e:
                logger.error(f"Error sending notification via {notifier_name}: {e}")
                results[notifier_name] = False

        return results
