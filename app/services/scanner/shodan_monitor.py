"""
Shodan integration service
Queries Shodan for open ports and vulnerabilities
"""

import logging
from typing import List, Dict, Set, Optional
from app.utils.cli_tools import query_shodan, shodan_host_info
from app.config import settings

logger = logging.getLogger(__name__)


class ShodanMonitor:
    """Service for Shodan monitoring"""

    def __init__(self, targets: List[str], query_mode: str = "ip"):
        """
        Initialize Shodan monitor

        Args:
            targets: List of IPs or domains to query
            query_mode: "ip" for IP lookup, "domain" for domain search
        """
        self.targets = targets
        self.query_mode = query_mode
        self.results = {}
        self.vulnerabilities = []

    def scan(self) -> Dict[str, any]:
        """
        Scan targets using Shodan
        
        Returns:
            Dict with Shodan results and vulnerabilities
        """
        import time
        
        if not settings.shodan_api_key:
            logger.warning("Shodan API key not configured, skipping Shodan scan")
            return {
                "shodan_results": {},
                "vulnerabilities": [],
                "stats": {"total": 0, "found": 0, "vulns": 0},
                "rate_limited_ips": [],
                "error": "Shodan API key not configured"
            }

        # Deduplicate targets
        unique_targets = list(set(self.targets))
        logger.info(f"Scanning {len(unique_targets)} unique targets with Shodan (from {len(self.targets)} total)")

        shodan_results = {}
        found_count = 0
        rate_limited_ips = []

        if self.query_mode == "ip":
            # Direct IP lookup with throttling
            for idx, ip in enumerate(unique_targets):
                try:
                    host_info = shodan_host_info(ip)
                    if host_info:
                        processed = self._process_host_info(ip, host_info)
                        shodan_results[ip] = processed
                        found_count += 1
                except Exception as e:
                    error_msg = str(e)
                    if "Rate limit" in error_msg:
                        rate_limited_ips.append(ip)
                        logger.warning(f"Shodan rate limited for {ip}, will retry in next scan")
                    else:
                        logger.error(f"Shodan lookup failed for {ip}: {e}")
                
                # Throttle: delay between requests (skip delay on last item)
                if idx < len(unique_targets) - 1:
                    time.sleep(0.5)  # 500ms delay = ~2 req/sec max

        elif self.query_mode == "domain":
            # Search query (can search multiple at once)
            for target in unique_targets:
                try:
                    query = f"hostname:{target}"
                    results = query_shodan(query, limit=100)

                    if results:
                        for result in results:
                            ip = result.get("ip_str", "")
                            if ip and ip not in shodan_results:  # Avoid duplicates
                                processed = self._process_search_result(result)
                                shodan_results[ip] = processed
                                found_count += 1
                except Exception as e:
                    error_msg = str(e)
                    if "Rate limit" in error_msg:
                        logger.warning(f"Shodan rate limited for {target}")
                    else:
                        logger.error(f"Shodan search failed for {target}: {e}")
                
                # Throttle between domain searches
                time.sleep(0.5)

        result = {
            "shodan_results": shodan_results,
            "vulnerabilities": self.vulnerabilities,
            "stats": {
                "total": len(unique_targets),
                "found": found_count,
                "vulns": len(self.vulnerabilities),
                "rate_limited": len(rate_limited_ips)
            },
            "rate_limited_ips": rate_limited_ips
        }

        logger.info(
            f"Shodan scan complete: {found_count} hosts found, "
            f"{len(self.vulnerabilities)} vulnerabilities, "
            f"{len(rate_limited_ips)} rate-limited"
        )

        return result

    def _process_host_info(self, ip: str, host_info: Dict) -> Dict:
        """
        Process Shodan host info response

        Args:
            ip: IP address
            host_info: Raw Shodan host info

        Returns:
            Processed host data
        """
        ports = host_info.get("ports", [])
        hostnames = host_info.get("hostnames", [])
        vulns = host_info.get("vulns", [])
        org = host_info.get("org", "")
        country = host_info.get("country_name", "")

        # Extract service information
        services = []
        data_list = host_info.get("data", [])
        for service in data_list:
            services.append({
                "port": service.get("port"),
                "transport": service.get("transport", "tcp"),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "banner": service.get("data", "")[:200]  # Truncate banner
            })

        # Process vulnerabilities
        if vulns:
            for vuln in vulns:
                self.vulnerabilities.append({
                    "ip": ip,
                    "cve": vuln,
                    "hostnames": hostnames,
                    "severity": "unknown"  # Shodan doesn't always provide severity
                })

        return {
            "ip": ip,
            "ports": ports,
            "hostnames": hostnames,
            "vulns": vulns,
            "services": services,
            "org": org,
            "country": country
        }

    def _process_search_result(self, result: Dict) -> Dict:
        """
        Process Shodan search result

        Args:
            result: Raw Shodan search result

        Returns:
            Processed host data
        """
        ip = result.get("ip_str", "")
        port = result.get("port")
        hostnames = result.get("hostnames", [])
        vulns = result.get("vulns", [])
        org = result.get("org", "")
        product = result.get("product", "")

        # Process vulnerabilities
        if vulns:
            for vuln in vulns:
                self.vulnerabilities.append({
                    "ip": ip,
                    "port": port,
                    "cve": vuln,
                    "hostnames": hostnames,
                    "severity": "unknown"
                })

        return {
            "ip": ip,
            "ports": [port] if port else [],
            "hostnames": hostnames,
            "vulns": vulns,
            "services": [{
                "port": port,
                "product": product,
                "banner": result.get("data", "")[:200]
            }] if port else [],
            "org": org,
            "country": result.get("location", {}).get("country_name", "")
        }


def scan_with_shodan(
    targets: List[str],
    query_mode: str = "ip"
) -> Dict[str, any]:
    """
    Convenience function for Shodan scanning

    Args:
        targets: List of IPs or domains
        query_mode: "ip" or "domain"

    Returns:
        Shodan scan results
    """
    monitor = ShodanMonitor(targets, query_mode)
    return monitor.scan()
