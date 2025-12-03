"""
Subdomain diff logic
Detects new and removed subdomains
"""

import logging
from typing import List, Set, Dict
from app.models import EventType, SeverityLevel

logger = logging.getLogger(__name__)


def diff_subdomains(old_subdomains: List[str], new_subdomains: List[str]) -> List[Dict]:
    """
    Compare two subdomain lists and generate events

    Args:
        old_subdomains: Previous subdomain list
        new_subdomains: Current subdomain list

    Returns:
        List of event dicts
    """
    old_set = set(old_subdomains) if old_subdomains else set()
    new_set = set(new_subdomains) if new_subdomains else set()

    # Find new and removed subdomains
    new_subs = new_set - old_set
    removed_subs = old_set - new_set

    events = []

    # Generate events for new subdomains
    for subdomain in sorted(new_subs):
        events.append({
            "type": EventType.SUBDOMAIN_NEW,
            "severity": SeverityLevel.INFO,
            "summary": f"New subdomain discovered: {subdomain}",
            "details": {
                "subdomain": subdomain,
                "change_type": "new"
            },
            "related_entities": {
                "subdomain": subdomain
            }
        })

    # Generate events for removed subdomains
    for subdomain in sorted(removed_subs):
        events.append({
            "type": EventType.SUBDOMAIN_REMOVED,
            "severity": SeverityLevel.LOW,
            "summary": f"Subdomain removed: {subdomain}",
            "details": {
                "subdomain": subdomain,
                "change_type": "removed"
            },
            "related_entities": {
                "subdomain": subdomain
            }
        })

    if events:
        logger.info(f"Subdomain changes: {len(new_subs)} new, {len(removed_subs)} removed")

    return events
