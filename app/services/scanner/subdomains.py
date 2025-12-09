"""
Subdomain discovery service
Aggregates results from multiple sources: subfinder, assetfinder, crt.sh, etc.
"""

import logging
import os
import requests
import zipfile
from pathlib import Path
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.utils.cli_tools import run_subfinder, run_assetfinder
from app.utils.helpers import crtsh_query, clean_subdomain, is_subdomain, deduplicate_list

logger = logging.getLogger(__name__)


class SubdomainDiscovery:
    """Service for discovering subdomains from multiple sources"""

    def __init__(self, domains: List[str], enabled_sources: List[str] = None):
        """
        Initialize subdomain discovery

        Args:
            domains: List of root domains to discover subdomains for
            enabled_sources: List of sources to use (default: all available)
        """
        self.domains = domains
        self.enabled_sources = enabled_sources or [
            "subfinder",
            "assetfinder",
            "crtsh"
        ]
        self.results = {}
        self.all_subdomains = set()

    def run_chaos(self, domain: str) -> Set[str]:
        """Run Chaos (ProjectDiscovery) for subdomain discovery"""
        logger.info(f"Running Chaos Dump for {domain}...")

        # Use temporary directory for chaos data
        chaos_dir = Path(os.path.join("/tmp", "assetmon_chaos"))
        chaos_dir.mkdir(exist_ok=True)

        try:
            # Download chaos index
            index_url = "https://chaos-data.projectdiscovery.io/index.json"
            response = requests.get(index_url, timeout=30)
            index_data = response.json()

            # Find domain in index
            chaos_url = None
            for entry in index_data:
                if entry.get('domain') == domain:
                    chaos_url = entry.get('URL')
                    break

            if chaos_url:
                logger.info(f"Downloading Chaos data for {domain}...")

                # Download zip file
                zip_response = requests.get(chaos_url, timeout=60)
                zip_file = chaos_dir / f"{domain}.zip"

                with open(zip_file, 'wb') as f:
                    f.write(zip_response.content)

                # Extract zip
                with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                    zip_ref.extractall(chaos_dir)

                # Read all txt files
                subs = set()
                for txt_file in chaos_dir.glob("*.txt"):
                    with open(txt_file, 'r') as f:
                        subs.update([line.strip() for line in f if line.strip()])

                # Cleanup zip file (temp dir will be cleaned by OS eventually, or explicitly here)
                zip_file.unlink()
                for txt_file in chaos_dir.glob("*.txt"):
                    txt_file.unlink()

                logger.info(f"Chaos Dump: {len(subs)} subdomains found for {domain}")
                return subs
            else:
                logger.info(f"Chaos Dump: Not found for {domain}")
                return set()

        except Exception as e:
            logger.error(f"Chaos error for {domain}: {e}")
            return set()

    def discover(self) -> Dict[str, any]:
        """
        Run subdomain discovery from all enabled sources
        
        Returns:
            Dict with results: {
                "subdomains": List[str],
                "count": int,
                "sources": {
                    "subfinder": {"count": int, "subdomains": List[str]},
                    ...
                }
            }
        """
        logger.info(f"Starting subdomain discovery for {len(self.domains)} domain(s)")
        logger.info(f"Enabled sources: {', '.join(self.enabled_sources)}")

        source_results = {}

        # Run subfinder (supports multiple domains at once)
        if "subfinder" in self.enabled_sources:
            try:
                logger.info("Running subfinder...")
                subdomains = run_subfinder(self.domains)
                cleaned = self._clean_subdomains(subdomains)
                source_results["subfinder"] = {
                    "count": len(cleaned),
                    "subdomains": cleaned
                }
                self.all_subdomains.update(cleaned)
            except Exception as e:
                logger.error(f"subfinder failed: {e}")
                source_results["subfinder"] = {"count": 0, "subdomains": [], "error": str(e)}

        # Run assetfinder, crtsh, and chaos per domain
        for domain in self.domains:
            if "assetfinder" in self.enabled_sources:
                try:
                    logger.info(f"Running assetfinder for {domain}...")
                    subdomains = run_assetfinder(domain)
                    cleaned = self._clean_subdomains(subdomains)
                    
                    if "assetfinder" not in source_results:
                        source_results["assetfinder"] = {"count": 0, "subdomains": []}
                    
                    source_results["assetfinder"]["count"] += len(cleaned)
                    source_results["assetfinder"]["subdomains"].extend(cleaned)
                    self.all_subdomains.update(cleaned)
                except Exception as e:
                    logger.error(f"assetfinder failed for {domain}: {e}")

            if "crtsh" in self.enabled_sources:
                try:
                    logger.info(f"Running crt.sh query for {domain}...")
                    subdomains = crtsh_query(domain)
                    cleaned = self._clean_subdomains(subdomains)
                    
                    if "crtsh" not in source_results:
                        source_results["crtsh"] = {"count": 0, "subdomains": []}
                        
                    source_results["crtsh"]["count"] += len(cleaned)
                    source_results["crtsh"]["subdomains"].extend(cleaned)
                    self.all_subdomains.update(cleaned)
                except Exception as e:
                    logger.error(f"crt.sh failed for {domain}: {e}")

            if "chaos" in self.enabled_sources:
                try:
                    subdomains = list(self.run_chaos(domain))
                    cleaned = self._clean_subdomains(subdomains)
                    
                    if "chaos" not in source_results:
                        source_results["chaos"] = {"count": 0, "subdomains": []}
                        
                    source_results["chaos"]["count"] += len(cleaned)
                    source_results["chaos"]["subdomains"].extend(cleaned)
                    self.all_subdomains.update(cleaned)
                except Exception as e:
                    logger.error(f"chaos failed for {domain}: {e}")


        # Aggregate results
        all_subdomains_list = sorted(list(self.all_subdomains))

        result = {
            "subdomains": all_subdomains_list,
            "count": len(all_subdomains_list),
            "domains_scanned": self.domains,
            "sources": source_results
        }

        logger.info(f"Subdomain discovery complete: {result['count']} unique subdomains found")

        return result

    def _clean_subdomains(self, subdomains: List[str]) -> List[str]:
        """
        Clean and validate subdomains

        Args:
            subdomains: Raw list of subdomains

        Returns:
            Cleaned and validated list
        """
        cleaned = []
        for sub in subdomains:
            sub = clean_subdomain(sub)

            # Validate it's actually a subdomain of one of our target domains
            if any(is_subdomain(sub, domain) for domain in self.domains):
                cleaned.append(sub)

        return deduplicate_list(cleaned)


def discover_subdomains(
    domains: List[str],
    sources: List[str] = None
) -> Dict[str, any]:
    """
    Convenience function for subdomain discovery

    Args:
        domains: List of domains to scan
        sources: List of sources to use (optional)

    Returns:
        Discovery results dict
    """
    discovery = SubdomainDiscovery(domains, sources)
    return discovery.discover()
