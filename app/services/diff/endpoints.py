"""
Endpoints diff logic
Detects new endpoints and JS files
"""

import logging
from typing import List, Dict
from app.models import EventType, SeverityLevel
from app.utils.helpers import is_js_file

logger = logging.getLogger(__name__)


def diff_endpoints(old_endpoints: Dict, new_endpoints: Dict, old_analysis: Dict = None) -> List[Dict]:
    """
    Compare endpoint lists and generate events

    Args:
        old_endpoints: Previous endpoints {urls: [...], js_files: [...]}
        new_endpoints: Current endpoints {urls: [...], js_files: [...], js_file_analysis: {...}}
        old_analysis: Previous JS file analysis results

    Returns:
        List of event dicts
    """
    old_endpoints = old_endpoints or {}
    new_endpoints = new_endpoints or {}
    old_analysis = old_analysis or {}

    events = []

    # URLs diff
    old_urls = set(old_endpoints.get("urls", []))
    new_urls = set(new_endpoints.get("urls", []))

    new_discovered_urls = new_urls - old_urls

    # Generate events for new URLs (excluding JS files, they'll be handled separately)
    for url in sorted(new_discovered_urls):
        if not is_js_file(url):
            # Determine severity based on URL pattern
            severity = SeverityLevel.LOW

            # Higher severity for API endpoints
            url_lower = url.lower()
            if any(pattern in url_lower for pattern in ["/api/", "/v1/", "/v2/", "/graphql", ".json"]):
                severity = SeverityLevel.MEDIUM

            events.append({
                "type": EventType.ENDPOINT_NEW,
                "severity": severity,
                "summary": f"New endpoint discovered: {url}",
                "details": {
                    "url": url,
                    "change_type": "new"
                },
                "related_entities": {
                    "url": url
                }
            })

    # JS files diff (higher priority)
    old_js = set(old_endpoints.get("js_files", []))
    new_js = set(new_endpoints.get("js_files", []))
    new_analysis = new_endpoints.get("js_file_analysis", {})

    new_discovered_js = new_js - old_js
    removed_js = old_js - new_js

    # New JS files
    for js_file in sorted(new_discovered_js):
        # Get analysis for new file
        analysis = new_analysis.get(js_file, {})
        status = analysis.get('status', 'unknown')
        is_active = status == 'active'

        # Filter out unknown/inactive files per user request
        if status != 'active':
            continue

        events.append({
            "type": EventType.JS_FILE_NEW,
            "severity": SeverityLevel.MEDIUM,
            "summary": f"New JS file discovered: {js_file.split('/')[-1]} ({status})",
            "details": {
                "url": js_file,
                "change_type": "new",
                "file_type": "javascript",
                "status": status,
                "is_active": is_active
            },
            "related_entities": {
                "url": js_file,
                "status": status
            }
        })

    # Removed JS files
    for js_file in sorted(removed_js):
        events.append({
            "type": EventType.JS_FILE_NEW,  # Reusing same type
            "severity": SeverityLevel.INFO,
            "summary": f"JS file removed: {js_file.split('/')[-1]}",
            "details": {
                "url": js_file,
                "change_type": "removed",
                "file_type": "javascript"
            },
            "related_entities": {
                "url": js_file
            }
        })

    # Status changes for existing JS files
    common_js = old_js & new_js
    for js_file in common_js:
        old_file_analysis = old_analysis.get(js_file, {})
        new_file_analysis = new_analysis.get(js_file, {})

        old_status = old_file_analysis.get('status', 'unknown')
        new_status = new_file_analysis.get('status', 'unknown')

        # Detect status change
        if old_status != new_status and new_status != 'unknown':
            severity = SeverityLevel.MEDIUM if new_status == 'inactive' else SeverityLevel.LOW

            events.append({
                "type": EventType.JS_FILE_NEW,  # Reusing same type
                "severity": severity,
                "summary": f"JS file status changed: {js_file.split('/')[-1]} ({old_status} → {new_status})",
                "details": {
                    "url": js_file,
                    "change_type": "status_changed",
                    "file_type": "javascript",
                    "old_status": old_status,
                    "new_status": new_status,
                    "old_analysis": old_file_analysis,
                    "new_analysis": new_file_analysis
                },
                "related_entities": {
                    "url": js_file,
                    "old_status": old_status,
                    "new_status": new_status
                }
            })

    if events:
        logger.info(
            f"Endpoint changes: {len(new_discovered_urls)} new URLs, "
            f"{len(new_discovered_js)} new JS files, {len(removed_js)} removed JS files"
        )

    return events
