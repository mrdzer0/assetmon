"""
HTTP diff logic
Detects changes in HTTP status, title, content length
"""

import logging
from typing import List, Dict
from app.models import EventType, SeverityLevel
from app.utils.helpers import is_significant_content_change

logger = logging.getLogger(__name__)


def diff_http(old_http: Dict[str, Dict], new_http: Dict[str, Dict]) -> List[Dict]:
    """
    Compare HTTP records and generate events

    Args:
        old_http: Previous HTTP records {url: {status_code, title, content_length, ...}}
        new_http: Current HTTP records

    Returns:
        List of event dicts
    """
    old_http = old_http or {}
    new_http = new_http or {}

    events = []

    # Get all URLs (union of old and new)
    all_urls = set(old_http.keys()) | set(new_http.keys())

    for url in sorted(all_urls):
        old_record = old_http.get(url, {})
        new_record = new_http.get(url, {})

        # Skip if both are empty
        if not old_record and not new_record:
            continue

        # Status code changes
        old_status = old_record.get("status_code")
        new_status = new_record.get("status_code")

        if old_status and new_status and old_status != new_status:
            # Determine severity based on status code change
            severity = SeverityLevel.MEDIUM

            # Critical if going from 2xx/3xx to 4xx/5xx or vice versa
            if (200 <= old_status < 400 and new_status >= 400) or \
               (old_status >= 400 and 200 <= new_status < 400):
                severity = SeverityLevel.HIGH

            events.append({
                "type": EventType.HTTP_STATUS_CHANGED,
                "severity": severity,
                "summary": f"HTTP status changed for {url}: {old_status} -> {new_status}",
                "details": {
                    "url": url,
                    "old_status": old_status,
                    "new_status": new_status
                },
                "related_entities": {
                    "url": url,
                    "status_code": new_status
                }
            })

        # Title changes
        old_title = old_record.get("title", "")
        new_title = new_record.get("title", "")

        if old_title and new_title and old_title != new_title:
            events.append({
                "type": EventType.HTTP_TITLE_CHANGED,
                "severity": SeverityLevel.LOW,
                "summary": f"Page title changed for {url}",
                "details": {
                    "url": url,
                    "old_title": old_title,
                    "new_title": new_title
                },
                "related_entities": {
                    "url": url
                }
            })

        # Content length changes (significant only)
        old_length = old_record.get("content_length", 0) or 0
        new_length = new_record.get("content_length", 0) or 0

        if is_significant_content_change(old_length, new_length, threshold_percent=30.0):
            events.append({
                "type": EventType.HTTP_CONTENT_CHANGED,
                "severity": SeverityLevel.LOW,
                "summary": f"Significant content change for {url}: {old_length} -> {new_length} bytes",
                "details": {
                    "url": url,
                    "old_length": old_length,
                    "new_length": new_length,
                    "change_percent": round(
                        ((new_length - old_length) / old_length * 100) if old_length > 0 else 100,
                        2
                    )
                },
                "related_entities": {
                    "url": url
                }
            })

    if events:
        logger.info(f"HTTP changes: {len(events)} changes detected")

    return events
