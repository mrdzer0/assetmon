"""
DNS diff logic
Detects changes in A records and CNAME records
"""

import logging
from typing import List, Dict
from app.models import EventType, SeverityLevel

logger = logging.getLogger(__name__)


def diff_dns(old_dns: Dict[str, Dict], new_dns: Dict[str, Dict]) -> List[Dict]:
    """
    Compare DNS records and generate events

    Args:
        old_dns: Previous DNS records {subdomain: {a: [...], cname: [...]}}
        new_dns: Current DNS records

    Returns:
        List of event dicts
    """
    old_dns = old_dns or {}
    new_dns = new_dns or {}

    events = []

    # Get all subdomains (union of old and new)
    all_subdomains = set(old_dns.keys()) | set(new_dns.keys())

    for subdomain in sorted(all_subdomains):
        old_record = old_dns.get(subdomain, {})
        new_record = new_dns.get(subdomain, {})

        # Skip if both are empty
        if not old_record and not new_record:
            continue

        old_a = set(old_record.get("a", []))
        new_a = set(new_record.get("a", []))

        old_cname = set(old_record.get("cname", []))
        new_cname = set(new_record.get("cname", []))

        # Check A record changes
        if old_a != new_a:
            added_ips = new_a - old_a
            removed_ips = old_a - new_a

            # Determine severity based on change type
            severity = SeverityLevel.MEDIUM if (added_ips or removed_ips) else SeverityLevel.LOW

            summary = f"DNS A record changed for {subdomain}"
            if added_ips:
                summary += f" (+{len(added_ips)} IPs)"
            if removed_ips:
                summary += f" (-{len(removed_ips)} IPs)"

            events.append({
                "type": EventType.DNS_CHANGED,
                "severity": severity,
                "summary": summary,
                "details": {
                    "subdomain": subdomain,
                    "change_type": "a_record",
                    "old_ips": sorted(list(old_a)),
                    "new_ips": sorted(list(new_a)),
                    "added_ips": sorted(list(added_ips)),
                    "removed_ips": sorted(list(removed_ips))
                },
                "related_entities": {
                    "subdomain": subdomain,
                    "ips": sorted(list(new_a))
                }
            })

        # Check CNAME changes
        if old_cname != new_cname:
            added_cnames = new_cname - old_cname
            removed_cnames = old_cname - new_cname

            severity = SeverityLevel.MEDIUM

            summary = f"DNS CNAME changed for {subdomain}"
            if added_cnames:
                summary += f" (now: {', '.join(added_cnames)})"

            events.append({
                "type": EventType.DNS_CHANGED,
                "severity": severity,
                "summary": summary,
                "details": {
                    "subdomain": subdomain,
                    "change_type": "cname",
                    "old_cnames": sorted(list(old_cname)),
                    "new_cnames": sorted(list(new_cname)),
                    "added_cnames": sorted(list(added_cnames)),
                    "removed_cnames": sorted(list(removed_cnames))
                },
                "related_entities": {
                    "subdomain": subdomain,
                    "cnames": sorted(list(new_cname))
                }
            })

    if events:
        logger.info(f"DNS changes: {len(events)} changes detected")

    return events
