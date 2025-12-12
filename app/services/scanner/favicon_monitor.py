"""
Favicon Monitor
Scan for shadow assets by cross-referencing favicon hashes on Shodan
"""

import logging
import base64
import mmh3
import requests
import time
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse
from app.utils.cli_tools import query_shodan
from app.config import settings

logger = logging.getLogger(__name__)


class FaviconMonitor:
    """Service for Favicon cross-referencing"""

    def __init__(self, known_domains: List[str], known_ips: List[str], root_domains: List[str] = None):
        """
        Initialize Favicon monitor
        
        Args:
            known_domains: List of known domains/subdomains to exclude from results
            known_ips: List of known IPs to exclude from results
            root_domains: List of root project domains for keyword extraction (e.g., ['julo.co.id', 'julofinance.com'])
        """
        self.known_domains = set(known_domains)
        self.known_ips = set(known_ips)
        
        # Extract keywords ONLY from root domains (not subdomains)
        self.ownership_keywords = self._extract_keywords(root_domains or [])
        logger.info(f"Favicon Monitor initialized with keywords: {self.ownership_keywords}")
        
        self.session = requests.Session()
        # Browser-like headers to avoid 403s
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def _extract_keywords(self, domains: List[str]) -> Set[str]:
        """Extract unique keywords from domain names for ownership validation"""
        keywords = set()
        for domain in domains:
            # Extract the main part of the domain (before TLD)
            # e.g., "julo.co.id" -> "julo", "julofinance.com" -> "julofinance"
            parts = domain.lower().split('.')
            if len(parts) >= 2:
                # Get the main domain name (not subdomains or TLD)
                # For "api.julo.co.id" -> we want "julo"
                # For "julofinance.com" -> we want "julofinance"
                for part in parts:
                    # Skip common TLDs and short parts
                    if part not in ('com', 'co', 'id', 'io', 'net', 'org', 'dev', 'app', 'www', 'api', 'staging', 'dev', 'prod'):
                        if len(part) >= 4:  # Only consider meaningful keywords
                            keywords.add(part)
        return keywords

    # Known default favicons to ignore (minimizes false positives)
    IGNORED_HASHES = {
        -1341917731: "Vercel Default",
        -2070047203: "Vercel Default (Variant)",  # Triangle logo variant
        1349811561: "React Default", 
        864985040: "Node.js Default",
        0: "Empty File",
        -1: "Invalid"
    }

    def get_favicon_hash(self, url: str) -> Optional[int]:
        """
        Download favicon and calculate MMH3 hash
        
        Args:
            url: Base URL (e.g., https://example.com)
            
        Returns:
            MMH3 hash integer or None if failed
        """
        try:
            # Construct favicon URL
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            favicon_url = f"{base_url}/favicon.ico"
            
            response = self.session.get(favicon_url, timeout=10, allow_redirects=True, verify=False)
            
            if response.status_code == 200 and len(response.content) > 0:
                # Shodan hashing algorithm:
                # 1. Base64 encode the content
                # 2. Add newlines every 76 chars (MIME standard)
                # 3. Calculate MMH3 hash
                
                favicon = base64.encodebytes(response.content)
                hash_val = mmh3.hash(favicon)
                return hash_val, favicon_url
                
        except Exception as e:
            # logger.debug(f"Failed to fetch favicon from {url}: {e}")
            pass
            
        return None, None

    def scan(self, targets: List[str]) -> Dict:
        """
        Scan targets for favicons and cross-reference with Shodan
        
        Args:
            targets: List of alive URLs to check for favicons
            
        Returns:
            Dict with findings
        """
        if not settings.shodan_api_key:
            logger.warning("Shodan API key not configured, skipping Favicon scan")
            return {"error": "Shodan API key missing"}

        logger.info(f"Starting Favicon scan for {len(targets)} targets...")
        
        findings = []
        hashes_checked = set()
        
        # Limit targets to avoid taking too long (favicons are usually consistent across subs)
        # We'll take a sample of unique domains + some random others
        # Actually, let's just try all unique root domains first? 
        # For now, just process the list but skip duplicate hashes
        
        for url in targets:
            hash_val, favicon_url = self.get_favicon_hash(url)
            
            if hash_val and hash_val not in hashes_checked:
                hashes_checked.add(hash_val)

                # Check if hash is in ignore list
                if hash_val in self.IGNORED_HASHES:
                    logger.info(f"Skipping ignored favicon hash {hash_val} ({self.IGNORED_HASHES[hash_val]}) at {favicon_url}")
                    continue

                logger.info(f"Found favicon at {favicon_url} (hash: {hash_val})")
                
                # Query Shodan
                self._query_shodan_for_hash(hash_val, favicon_url, findings)
                
                # Sleep briefly to avoid rate limits
                time.sleep(1)

        result = {
            "findings": findings,
            "stats": {
                "hashes_checked": len(hashes_checked),
                "shadow_assets_found": len(findings)
            }
        }
        
        logger.info(f"Favicon scan complete: {len(findings)} shadow assets found")
        return result

    def _query_shodan_for_hash(self, hash_val: int, favicon_url: str, findings: List[Dict]):
        """Query Shodan for a specific favicon hash"""
        try:
            query = f"http.favicon.hash:{hash_val}"
            results = query_shodan(query, limit=100)
            
            if results:
                for match in results:
                    ip = match.get("ip_str")
                    hostnames = match.get("hostnames", [])
                    
                    # FILTER 1: Check if this asset is already known
                    if self._is_known_asset(ip, hostnames):
                        continue
                    
                    # FILTER 2: Validate ownership by checking for project keywords
                    if not self._validate_ownership(match):
                        logger.debug(f"Skipping {ip} - no ownership keywords found in hostnames/org/banner")
                        continue
                        
                    # Found a shadow asset!
                    findings.append({
                        "ip": ip,
                        "port": match.get("port"),
                        "hostnames": hostnames,
                        "org": match.get("org", ""),
                        "country": match.get("location", {}).get("country_name", ""),
                        "favicon_hash": hash_val,
                        "original_favicon_url": favicon_url,
                        "shodan_data": {
                            "data": match.get("data", "")[:100], # Preview
                            "os": match.get("os"),
                            "isp": match.get("isp")
                        }
                    })
                    
        except Exception as e:
            logger.error(f"Shodan query failed for hash {hash_val}: {e}")

    def _is_known_asset(self, ip: str, hostnames: List[str]) -> bool:
        """Check if asset is already in our project scope"""
        if ip in self.known_ips:
            return True
            
        for hostname in hostnames:
            if hostname in self.known_domains:
                return True
            # Check if it's a subdomain of a known domain
            for known_domain in self.known_domains:
                if hostname.endswith(f".{known_domain}"):
                    return True
                    
        return False

    def _validate_ownership(self, match: Dict) -> bool:
        """
        Validate if Shodan result likely belongs to the project by checking
        for keyword presence in hostnames, banner, or org.
        
        Returns True if ownership is validated (should be reported).
        """
        if not self.ownership_keywords:
            # No keywords to validate against, accept all
            return True
            
        # Data to check
        hostnames = match.get("hostnames", [])
        org = match.get("org", "").lower()
        banner = match.get("data", "").lower()[:500]  # First 500 chars
        isp = match.get("isp", "").lower()
        
        # Check hostnames
        for hostname in hostnames:
            hostname_lower = hostname.lower()
            for keyword in self.ownership_keywords:
                if keyword in hostname_lower:
                    logger.debug(f"Ownership validated: keyword '{keyword}' found in hostname '{hostname}'")
                    return True
        
        # Check org
        for keyword in self.ownership_keywords:
            if keyword in org:
                logger.debug(f"Ownership validated: keyword '{keyword}' found in org '{org}'")
                return True
                
        # Check banner (HTTP response body preview)
        for keyword in self.ownership_keywords:
            if keyword in banner:
                logger.debug(f"Ownership validated: keyword '{keyword}' found in banner")
                return True
                
        # Check ISP
        for keyword in self.ownership_keywords:
            if keyword in isp:
                logger.debug(f"Ownership validated: keyword '{keyword}' found in ISP '{isp}'")
                return True
        
        return False
