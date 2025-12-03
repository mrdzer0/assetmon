"""
DNS monitoring service
Resolves DNS records and detects potential subdomain takeovers
"""

import logging
from typing import List, Dict, Set, Optional
from app.utils.cli_tools import run_dnsx
from app.utils.helpers import parse_takeover_patterns

logger = logging.getLogger(__name__)


# Known dead service patterns for subdomain takeover detection
TAKEOVER_SERVICES = {
    "vercel.app": "Vercel",
    "vercel.com": "Vercel",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokussl.com": "Heroku",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3",
    "azurewebsites.net": "Azure",
    "cloudfront.net": "CloudFront",
    "wpengine.com": "WP Engine",
    "pantheonsite.io": "Pantheon",
    "bitbucket.io": "Bitbucket",
    "fastly.net": "Fastly",
    "ghost.io": "Ghost",
    "surge.sh": "Surge",
    "readme.io": "Readme",
    "helpjuice.com": "HelpJuice",
    "helpscoutdocs.com": "HelpScout",
    "uservoice.com": "UserVoice",
    "zendesk.com": "Zendesk",
    "freshdesk.com": "Freshdesk",
    "desk.com": "Desk",
    "tictail.com": "Tictail",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "bigcartel.com": "Big Cartel",
    "statuspage.io": "StatusPage",
    "cargocollective.com": "Cargo",
    "squarespace.com": "Squarespace",
    "smartjobboard.com": "SmartJobBoard",
    "campaignmonitor.com": "Campaign Monitor",
}


class DNSMonitor:
    """Service for DNS monitoring and takeover detection"""

    def __init__(self, subdomains: List[str], rate_limit: Optional[int] = None):
        """
        Initialize DNS monitor

        Args:
            subdomains: List of subdomains to resolve
            rate_limit: DNS query rate limit
        """
        self.subdomains = subdomains
        self.rate_limit = rate_limit
        self.results = {}
        self.takeover_findings = []

    def resolve(self) -> Dict[str, any]:
        """
        Resolve DNS records for all subdomains

        Returns:
            Dict with DNS records and takeover findings
        """
        logger.info(f"Resolving DNS for {len(self.subdomains)} subdomains")

        if not self.subdomains:
            return {
                "dns_records": {},
                "takeover_findings": [],
                "stats": {"total": 0, "resolved": 0, "failed": 0}
            }

        # Run dnsx to get A and CNAME records
        raw_results = run_dnsx(
            self.subdomains,
            resolve_a=True,
            resolve_cname=True,
            rate_limit=self.rate_limit
        )

        # Process results
        dns_records = {}
        resolved_count = 0
        failed_count = 0

        for record in raw_results:
            subdomain = record.get("host", "")
            if not subdomain:
                continue

            a_records = record.get("a", [])
            cname_records = record.get("cname", [])

            dns_records[subdomain] = {
                "a": a_records if isinstance(a_records, list) else [a_records] if a_records else [],
                "cname": cname_records if isinstance(cname_records, list) else [cname_records] if cname_records else [],
                "has_resolution": bool(a_records or cname_records)
            }

            if a_records or cname_records:
                resolved_count += 1
            else:
                failed_count += 1

            # Check for potential takeover
            self._check_takeover(subdomain, dns_records[subdomain])

        # Check subdomains that didn't appear in results (might be NXDOMAIN)
        for subdomain in self.subdomains:
            if subdomain not in dns_records:
                dns_records[subdomain] = {
                    "a": [],
                    "cname": [],
                    "has_resolution": False,
                    "nxdomain": True
                }
                failed_count += 1

        result = {
            "dns_records": dns_records,
            "takeover_findings": self.takeover_findings,
            "stats": {
                "total": len(self.subdomains),
                "resolved": resolved_count,
                "failed": failed_count,
                "potential_takeovers": len(self.takeover_findings)
            }
        }

        logger.info(
            f"DNS resolution complete: {resolved_count} resolved, "
            f"{failed_count} failed, {len(self.takeover_findings)} potential takeovers"
        )

        return result

    def _check_takeover(self, subdomain: str, dns_record: Dict):
        """
        Check if subdomain is potentially vulnerable to takeover

        Args:
            subdomain: The subdomain to check
            dns_record: DNS record data
        """
        cname_records = dns_record.get("cname", [])
        a_records = dns_record.get("a", [])

        if not cname_records:
            return

        for cname in cname_records:
            cname_lower = cname.lower()

            # Check 1: CNAME pointing to known dead service patterns
            detected_service = None
            for pattern, service_name in TAKEOVER_SERVICES.items():
                if pattern in cname_lower:
                    detected_service = service_name
                    break

            if detected_service:
                # CNAME points to a service that could be vulnerable
                finding = {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": detected_service,
                    "reason": "cname_dead_service",
                    "severity": "high",
                    "description": f"CNAME points to {detected_service} which may be unclaimed"
                }

                # If there are no A records, it's more suspicious
                if not a_records:
                    finding["severity"] = "critical"
                    finding["description"] += " (no A record resolution)"

                self.takeover_findings.append(finding)
                logger.warning(
                    f"Potential takeover: {subdomain} -> {cname} ({detected_service})"
                )

            # Check 2: CNAME exists but NXDOMAIN (doesn't resolve to A record)
            # This is handled by checking if CNAME exists but a_records is empty
            elif not a_records:
                finding = {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": "unknown",
                    "reason": "nxdomain_with_cname",
                    "severity": "medium",
                    "description": "CNAME exists but does not resolve to any A record"
                }
                self.takeover_findings.append(finding)
                logger.warning(
                    f"Potential takeover (NXDOMAIN): {subdomain} -> {cname}"
                )


def monitor_dns(subdomains: List[str], rate_limit: Optional[int] = None) -> Dict[str, any]:
    """
    Convenience function for DNS monitoring

    Args:
        subdomains: List of subdomains to monitor
        rate_limit: DNS query rate limit

    Returns:
        DNS monitoring results
    """
    monitor = DNSMonitor(subdomains, rate_limit)
    return monitor.resolve()
