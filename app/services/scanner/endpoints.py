"""
Endpoint discovery service
Collects URLs and JS files using waybackurls, gau, and katana
"""

import logging
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.utils.cli_tools import run_waybackurls, run_gau, run_katana
from app.utils.helpers import is_js_file, deduplicate_list, filter_urls_by_extension

logger = logging.getLogger(__name__)


class EndpointDiscovery:
    """Service for discovering endpoints and JS files"""

    def __init__(
        self,
        domains: List[str],
        subdomains: List[str] = None,
        enabled_sources: List[str] = None,
        crawl_depth: int = 2
    ):
        """
        Initialize endpoint discovery

        Args:
            domains: List of root domains
            subdomains: List of subdomains (for katana crawling)
            enabled_sources: List of sources to use (default: all)
            crawl_depth: Depth for katana crawler
        """
        self.domains = domains
        self.subdomains = subdomains or []
        self.enabled_sources = enabled_sources or ["waybackurls", "gau", "katana"]
        self.crawl_depth = crawl_depth
        self.all_urls = set()
        self.all_js_files = set()

    def discover(self) -> Dict[str, any]:
        """
        Run endpoint discovery from all enabled sources

        Returns:
            Dict with URLs, JS files, and source breakdown
        """
        logger.info(f"Starting endpoint discovery for {len(self.domains)} domain(s)")
        logger.info(f"Enabled sources: {', '.join(self.enabled_sources)}")

        source_results = {}

        # Run waybackurls (historical URLs from Wayback Machine)
        if "waybackurls" in self.enabled_sources:
            wayback_urls = []
            for domain in self.domains:
                try:
                    logger.info(f"Running waybackurls for {domain}...")
                    urls = run_waybackurls(domain)
                    wayback_urls.extend(urls)
                except Exception as e:
                    logger.error(f"waybackurls failed for {domain}: {e}")

            js_files = [url for url in wayback_urls if is_js_file(url)]
            self.all_urls.update(wayback_urls)
            self.all_js_files.update(js_files)

            source_results["waybackurls"] = {
                "urls_count": len(wayback_urls),
                "js_files_count": len(js_files)
            }

        # Run gau (GetAllUrls from multiple sources)
        if "gau" in self.enabled_sources:
            gau_urls = []
            for domain in self.domains:
                try:
                    logger.info(f"Running gau for {domain}...")
                    urls = run_gau(domain)
                    gau_urls.extend(urls)
                except Exception as e:
                    logger.error(f"gau failed for {domain}: {e}")

            js_files = [url for url in gau_urls if is_js_file(url)]
            self.all_urls.update(gau_urls)
            self.all_js_files.update(js_files)

            source_results["gau"] = {
                "urls_count": len(gau_urls),
                "js_files_count": len(js_files)
            }

        # Run katana (active web crawler)
        if "katana" in self.enabled_sources:
            # Prepare URLs for crawling (use http/https with subdomains)
            crawl_targets = []
            for subdomain in self.subdomains[:100]:  # Limit to 100 to avoid too long crawl
                crawl_targets.append(f"https://{subdomain}")

            if crawl_targets:
                try:
                    logger.info(f"Running katana on {len(crawl_targets)} targets...")
                    katana_urls = run_katana(
                        crawl_targets,
                        depth=self.crawl_depth,
                        js_crawl=True
                    )
                    js_files = [url for url in katana_urls if is_js_file(url)]
                    self.all_urls.update(katana_urls)
                    self.all_js_files.update(js_files)

                    source_results["katana"] = {
                        "urls_count": len(katana_urls),
                        "js_files_count": len(js_files)
                    }
                except Exception as e:
                    logger.error(f"katana failed: {e}")
                    source_results["katana"] = {
                        "urls_count": 0,
                        "js_files_count": 0,
                        "error": str(e)
                    }

        # Convert sets to sorted lists
        all_urls_list = sorted(list(self.all_urls))
        all_js_files_list = sorted(list(self.all_js_files))

        # Categorize URLs
        api_endpoints = self._identify_api_endpoints(all_urls_list)

        result = {
            "urls": all_urls_list,
            "js_files": all_js_files_list,
            "api_endpoints": api_endpoints,
            "stats": {
                "total_urls": len(all_urls_list),
                "total_js_files": len(all_js_files_list),
                "total_api_endpoints": len(api_endpoints)
            },
            "sources": source_results
        }

        logger.info(
            f"Endpoint discovery complete: {len(all_urls_list)} URLs, "
            f"{len(all_js_files_list)} JS files, {len(api_endpoints)} API endpoints"
        )

        return result

    def _identify_api_endpoints(self, urls: List[str]) -> List[str]:
        """
        Identify likely API endpoints from URLs

        Args:
            urls: List of URLs

        Returns:
            List of API endpoints
        """
        api_endpoints = []
        api_patterns = [
            "/api/",
            "/v1/",
            "/v2/",
            "/v3/",
            "/rest/",
            "/graphql",
            "/webhook",
            ".json",
            ".xml"
        ]

        for url in urls:
            url_lower = url.lower()
            if any(pattern in url_lower for pattern in api_patterns):
                api_endpoints.append(url)

        return api_endpoints


def discover_endpoints(
    domains: List[str],
    subdomains: List[str] = None,
    sources: List[str] = None,
    crawl_depth: int = 2
) -> Dict[str, any]:
    """
    Convenience function for endpoint discovery

    Args:
        domains: List of domains
        subdomains: List of subdomains
        sources: List of sources to use
        crawl_depth: Crawler depth for katana

    Returns:
        Endpoint discovery results
    """
    discovery = EndpointDiscovery(domains, subdomains, sources, crawl_depth)
    return discovery.discover()
