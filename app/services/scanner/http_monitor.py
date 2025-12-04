"""
HTTP monitoring service
Probes HTTP endpoints and collects status, title, technologies, etc.
"""

import logging
from typing import List, Dict, Optional
from app.utils.cli_tools import run_httpx
from app.utils.helpers import parse_takeover_fingerprints

logger = logging.getLogger(__name__)


class HTTPMonitor:
    """Service for HTTP probing and monitoring"""

    def __init__(
        self,
        targets: List[str],
        threads: Optional[int] = None,
        timeout: Optional[int] = None
    ):
        """
        Initialize HTTP monitor

        Args:
            targets: List of hosts/URLs to probe
            threads: Number of threads for concurrent probing
            timeout: Timeout per request
        """
        self.targets = targets
        self.threads = threads
        self.timeout = timeout
        self.results = {}
        self.takeover_findings = []

    def probe(self) -> Dict[str, any]:
        """
        Probe HTTP endpoints

        Returns:
            Dict with HTTP records and statistics
        """
        logger.info(f"Probing HTTP for {len(self.targets)} targets")

        if not self.targets:
            return {
                "http_records": {},
                "takeover_findings": [],
                "stats": {"total": 0, "success": 0, "failed": 0}
            }

        # Run httpx without screenshot (requires chromium)
        raw_results = run_httpx(
            self.targets,
            threads=self.threads,
            timeout=self.timeout,
            tech_detect=True,
            status_code=True,
            title=True,
            content_length=True,
            screenshot=False
        )

        # Process results
        http_records = {}
        success_count = 0
        failed_count = 0

        for record in raw_results:
            url = record.get("url", "")
            if not url:
                continue

            # Extract relevant fields
            status_code = record.get("status_code", record.get("status-code"))
            title = record.get("title", "")
            content_length = record.get("content_length", record.get("content-length", 0))
            technologies = record.get("technologies", record.get("tech", []))

            # Additional info
            ip = record.get("host", record.get("ip", ""))
            cname = record.get("cname", "")
            cdn = record.get("cdn", "")
            screenshot = record.get("screenshot", "")

            http_record = {
                "url": url,
                "status_code": status_code,
                "title": title,
                "content_length": content_length,
                "technologies": technologies if isinstance(technologies, list) else [],
                "ip": ip,
                "cname": cname,
                "cdn": cdn,
                "screenshot": screenshot,
                "timestamp": record.get("timestamp", "")
            }

            http_records[url] = http_record

            if status_code and 200 <= status_code < 500:
                success_count += 1
            else:
                failed_count += 1

            # Check for takeover fingerprints in title/body
            self._check_takeover_fingerprint(url, title, status_code)

        result = {
            "http_records": http_records,
            "takeover_findings": self.takeover_findings,
            "stats": {
                "total": len(self.targets),
                "success": success_count,
                "failed": failed_count,
                "potential_takeovers": len(self.takeover_findings)
            }
        }

        logger.info(
            f"HTTP probing complete: {success_count} successful, "
            f"{failed_count} failed, {len(self.takeover_findings)} potential takeovers"
        )

        return result

    def _check_takeover_fingerprint(
        self,
        url: str,
        title: Optional[str],
        status_code: Optional[int]
    ):
        """
        Check HTTP response for takeover fingerprints

        Args:
            url: The URL
            title: Page title
            status_code: HTTP status code
        """
        if not title:
            return

        # Get known takeover fingerprints
        fingerprints = parse_takeover_fingerprints()

        title_lower = title.lower()

        for fingerprint in fingerprints:
            if fingerprint.lower() in title_lower:
                finding = {
                    "url": url,
                    "status_code": status_code,
                    "title": title,
                    "fingerprint": fingerprint,
                    "reason": "http_fingerprint_match",
                    "severity": "high",
                    "description": f"HTTP response contains takeover fingerprint: '{fingerprint}'"
                }

                self.takeover_findings.append(finding)
                logger.warning(
                    f"Potential takeover (HTTP fingerprint): {url} - '{fingerprint}' found in title"
                )
                break


def monitor_http(
    targets: List[str],
    threads: Optional[int] = None,
    timeout: Optional[int] = None
) -> Dict[str, any]:
    """
    Convenience function for HTTP monitoring

    Args:
        targets: List of targets to probe
        threads: Number of threads
        timeout: Timeout per request

    Returns:
        HTTP monitoring results
    """
    monitor = HTTPMonitor(targets, threads, timeout)
    return monitor.probe()
