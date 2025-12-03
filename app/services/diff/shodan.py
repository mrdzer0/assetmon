"""
Shodan diff logic
Detects new ports and vulnerabilities
"""

import logging
from typing import List, Dict
from app.models import EventType, SeverityLevel

logger = logging.getLogger(__name__)


def diff_shodan(old_shodan: Dict[str, Dict], new_shodan: Dict[str, Dict], ip_to_subdomains: Dict[str, List[str]] = None) -> List[Dict]:
    """
    Compare Shodan results and generate events

    Args:
        old_shodan: Previous Shodan results {ip: {ports: [...], vulns: [...], ...}}
        new_shodan: Current Shodan results

    Returns:
        List of event dicts
    """
    old_shodan = old_shodan or {}
    new_shodan = new_shodan or {}
    if ip_to_subdomains is None:
        ip_to_subdomains = {}

    events = []

    # Get all IPs (union of old and new)
    all_ips = set(old_shodan.keys()) | set(new_shodan.keys())

    for ip in sorted(all_ips):
        related_subdomains = ip_to_subdomains.get(ip, [])
        old_record = old_shodan.get(ip, {})
        new_record = new_shodan.get(ip, {})

        # Skip if both are empty
        if not old_record and not new_record:
            continue

        # Port changes
        old_ports = set(old_record.get("ports", []))
        new_ports = set(new_record.get("ports", []))

        new_open_ports = new_ports - old_ports
        closed_ports = old_ports - new_ports

        # New open ports (potentially interesting)
        for port in sorted(new_open_ports):
            events.append({
                "type": EventType.PORT_NEW,
                "severity": SeverityLevel.MEDIUM,
                "summary": f"New open port detected on {ip}: {port}",
                "details": {
                    "ip": ip,
                    "port": port,
                    "hostnames": new_record.get("hostnames", []),
                    "subdomains": related_subdomains
                },
                "related_entities": {
                    "ip": ip,
                    "port": port
                }
            })

        # Closed ports (less critical)
        for port in sorted(closed_ports):
            events.append({
                "type": EventType.PORT_REMOVED,
                "severity": SeverityLevel.INFO,
                "summary": f"Port closed on {ip}: {port}",
                "details": {
                    "ip": ip,
                    "port": port,
                    "subdomains": related_subdomains
                },
                "related_entities": {
                    "ip": ip,
                    "port": port
                }
            })

        # Vulnerability changes
        old_vulns = set(old_record.get("vulns", []))
        new_vulns = set(new_record.get("vulns", []))

        new_vulnerabilities = new_vulns - old_vulns

        for vuln in sorted(new_vulnerabilities):
            events.append({
                "type": EventType.VULNERABILITY_FOUND,
                "severity": SeverityLevel.HIGH,
                "summary": f"New vulnerability found on {ip}: {vuln}",
                "details": {
                    "ip": ip,
                    "cve": vuln,
                    "hostnames": new_record.get("hostnames", []),
                    "subdomains": related_subdomains
                },
                "related_entities": {
                    "ip": ip,
                    "cve": vuln
                }
            })

    if events:
        logger.info(f"Shodan changes: {len(events)} changes detected")

    return events
