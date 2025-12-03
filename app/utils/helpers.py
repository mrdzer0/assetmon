"""
Helper utility functions
"""

import re
import logging
import requests
from typing import List, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def is_subdomain(hostname: str, parent_domain: str) -> bool:
    """
    Check if hostname is a subdomain of parent_domain

    Args:
        hostname: The hostname to check
        parent_domain: The parent domain

    Returns:
        True if hostname is subdomain of parent_domain
    """
    hostname = hostname.lower().strip('.')
    parent_domain = parent_domain.lower().strip('.')

    if hostname == parent_domain:
        return True

    return hostname.endswith('.' + parent_domain)


def extract_domain_from_url(url: str) -> str:
    """
    Extract domain from URL

    Args:
        url: Full URL

    Returns:
        Domain name
    """
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split('/')[0]


def is_js_file(url: str) -> bool:
    """
    Check if URL points to a JavaScript file

    Args:
        url: URL to check

    Returns:
        True if URL is a JS file
    """
    parsed = urlparse(url)
    path = parsed.path.lower()
    return path.endswith('.js') or path.endswith('.jsx')


def deduplicate_list(items: List[str]) -> List[str]:
    """
    Deduplicate list while preserving order

    Args:
        items: List of items

    Returns:
        Deduplicated list
    """
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def clean_subdomain(subdomain: str) -> str:
    """
    Clean and normalize subdomain

    Args:
        subdomain: Raw subdomain string

    Returns:
        Cleaned subdomain
    """
    subdomain = subdomain.strip().lower()

    # Remove protocol if present
    subdomain = re.sub(r'^https?://', '', subdomain)

    # Remove trailing slash
    subdomain = subdomain.rstrip('/')

    # Remove port if present
    subdomain = re.sub(r':\d+$', '', subdomain)

    return subdomain


def crtsh_query(domain: str) -> List[str]:
    """
    Query crt.sh for subdomains using certificate transparency logs

    Args:
        domain: Domain to query

    Returns:
        List of subdomains
    """
    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            data = response.json()

            for entry in data:
                name_value = entry.get('name_value', '')

                # Split by newlines (crt.sh returns multiple domains per entry)
                for subdomain in name_value.split('\n'):
                    subdomain = subdomain.strip()

                    # Skip wildcards
                    if '*' in subdomain:
                        continue

                    # Clean and validate
                    subdomain = clean_subdomain(subdomain)

                    if subdomain and is_subdomain(subdomain, domain):
                        subdomains.add(subdomain)

            logger.info(f"crt.sh found {len(subdomains)} subdomains for {domain}")
        else:
            logger.warning(f"crt.sh returned status code {response.status_code}")

    except Exception as e:
        logger.error(f"crt.sh query failed: {e}")

    return list(subdomains)


def filter_urls_by_extension(urls: List[str], extensions: List[str]) -> List[str]:
    """
    Filter URLs by file extensions

    Args:
        urls: List of URLs
        extensions: List of extensions to filter by (e.g., ['.js', '.jsx'])

    Returns:
        Filtered list of URLs
    """
    filtered = []
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in extensions):
            filtered.append(url)

    return filtered


def calculate_percentage_change(old_value: float, new_value: float) -> float:
    """
    Calculate percentage change between two values

    Args:
        old_value: Old value
        new_value: New value

    Returns:
        Percentage change (positive or negative)
    """
    if old_value == 0:
        return 100.0 if new_value > 0 else 0.0

    return ((new_value - old_value) / old_value) * 100


def is_significant_content_change(
    old_length: int,
    new_length: int,
    threshold_percent: float = 20.0
) -> bool:
    """
    Check if content length change is significant

    Args:
        old_length: Old content length
        new_length: New content length
        threshold_percent: Threshold percentage for significance

    Returns:
        True if change is significant
    """
    if old_length == 0 and new_length > 0:
        return True

    if old_length == 0:
        return False

    change_percent = abs(calculate_percentage_change(old_length, new_length))
    return change_percent >= threshold_percent


def parse_takeover_patterns() -> List[str]:
    """
    Get list of CNAME patterns that indicate potential takeover

    Returns:
        List of patterns
    """
    from app.config import settings
    return settings.takeover_cname_list


def parse_takeover_fingerprints() -> List[str]:
    """
    Get list of HTTP response fingerprints that indicate potential takeover

    Returns:
        List of fingerprints
    """
    from app.config import settings
    return settings.takeover_fingerprint_list


def normalize_ip(ip: str) -> str:
    """
    Normalize IP address

    Args:
        ip: IP address string

    Returns:
        Normalized IP
    """
    return ip.strip()


def batch_list(items: List, batch_size: int) -> List[List]:
    """
    Split list into batches

    Args:
        items: List to batch
        batch_size: Size of each batch

    Returns:
        List of batches
    """
    batches = []
    for i in range(0, len(items), batch_size):
        batches.append(items[i:i + batch_size])
    return batches
