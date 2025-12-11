"""
Endpoint Categorizer
Identifies sensitive endpoints based on keywords and patterns
"""

import re
from typing import Dict, List, Set
from urllib.parse import urlparse


class EndpointCategorizer:
    """Categorize endpoints based on sensitive patterns"""

    # Sensitive categories and their keywords
    CATEGORIES = {
        'backup': {
            'keywords': ['backup', 'zip', 'tar', 'gz', 'sql', 'dump', 'bak', 'old'],
            'extensions': ['.zip', '.tar', '.gz', '.sql', '.bak', '.dump', '.tar.gz', '.tgz'],
            'severity': 'high',
            'description': 'Backup/Archive files',
            'icon': 'fa-archive',
            'color': '#dc3545'  # red
        },
        'dev': {
            'keywords': ['dev', 'admin', 'dashboard', 'test', 'staging', 'debug', 'console', 'panel'],
            'extensions': [],
            'severity': 'medium',
            'description': 'Development/Admin interfaces',
            'icon': 'fa-tools',
            'color': '#ffc107'  # yellow
        },
        'file': {
            'keywords': ['upload', 'download', 'file', 'document', 'attachment'],
            'extensions': ['.docx', '.pdf', '.xlsx', '.doc', '.xls', '.ppt', '.pptx'],
            'severity': 'medium',
            'description': 'Document files',
            'icon': 'fa-file-alt',
            'color': '#17a2b8'  # blue
        },
        'config': {
            'keywords': ['config', 'env', 'settings', 'conf', '.env', 'configuration'],
            'extensions': ['.env', '.config', '.conf', '.ini', '.yaml', '.yml', '.json'],
            'severity': 'high',
            'description': 'Configuration files',
            'icon': 'fa-cog',
            'color': '#dc3545'  # red
        },
        'auth': {
            'keywords': ['login', 'auth', 'signin', 'signup', 'register', 'password', 'token', 'session'],
            'extensions': [],
            'severity': 'medium',
            'description': 'Authentication endpoints',
            'icon': 'fa-key',
            'color': '#6f42c1'  # purple
        },
        'api': {
            'keywords': ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/'],
            'extensions': [],
            'severity': 'low',
            'description': 'API endpoints',
            'icon': 'fa-code',
            'color': '#28a745'  # green
        },
        'crypto': {
            'keywords': [
                'wallet', 'airdrop', 'claim', 'withdraw', 'transfer', 'web3',
                'contract', 'transaction', 'referral', 'mint', 'stake', 'swap',
                'bridge', 'approve', 'allowance', 'balance', 'connect-wallet',
                'metamask', 'ethereum', 'polygon', 'bsc', 'arbitrum', 'solana'
            ],
            'extensions': [],
            'severity': 'high',
            'description': 'Crypto/Web3 endpoints',
            'icon': 'fa-coins',
            'color': '#f7931a'  # bitcoin orange
        }
    }

    # File extensions to EXCLUDE from sensitive detection (common assets)
    EXCLUDED_EXTENSIONS = {
        '.woff', '.woff2', '.ttf', '.eot', '.otf',  # Fonts
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',  # Images
        '.mp4', '.webm', '.mp3', '.wav',  # Media
        '.css', '.less', '.scss', '.sass',  # Stylesheets
        '.map',  # Source maps (not sensitive by themselves)
    }

    @classmethod
    def categorize_url(cls, url: str) -> Dict:
        """
        Categorize a URL based on sensitive patterns

        Args:
            url: URL to categorize

        Returns:
            Dict with categories, severity, and flags
        """
        url_lower = url.lower()
        parsed = urlparse(url)
        path = parsed.path.lower()

        result = {
            'url': url,
            'categories': [],
            'highest_severity': 'low',
            'is_sensitive': False,
            'matched_keywords': [],
            'matched_extensions': []
        }

        # Skip common asset files - these are never sensitive
        for ext in cls.EXCLUDED_EXTENSIONS:
            if url_lower.endswith(ext):
                return result

        # Check each category
        for category_name, category_info in cls.CATEGORIES.items():
            matched_keywords = []
            matched_extensions = []

            # Check keywords using word boundaries (not substring match)
            for keyword in category_info['keywords']:
                # Use regex word boundary for accurate matching
                # This prevents "bold" matching "old" or "star" matching "tar"
                if keyword.startswith('/'):
                    # Path patterns like /api/ should match as-is
                    if keyword in url_lower:
                        matched_keywords.append(keyword)
                else:
                    # Use word boundary regex for other keywords
                    pattern = r'(?:^|[/_\-\.])' + re.escape(keyword) + r'(?:$|[/_\-\.])'
                    if re.search(pattern, url_lower):
                        matched_keywords.append(keyword)

            # Check extensions - must be at the very end of URL
            for ext in category_info['extensions']:
                if url_lower.endswith(ext):
                    matched_extensions.append(ext)

            # If any match found, add category
            if matched_keywords or matched_extensions:
                result['categories'].append({
                    'name': category_name,
                    'severity': category_info['severity'],
                    'description': category_info['description'],
                    'icon': category_info['icon'],
                    'color': category_info['color'],
                    'matched_keywords': matched_keywords,
                    'matched_extensions': matched_extensions
                })

                result['matched_keywords'].extend(matched_keywords)
                result['matched_extensions'].extend(matched_extensions)
                result['is_sensitive'] = True

                # Update highest severity
                if category_info['severity'] == 'high':
                    result['highest_severity'] = 'high'
                elif category_info['severity'] == 'medium' and result['highest_severity'] != 'high':
                    result['highest_severity'] = 'medium'

        return result

    @classmethod
    def categorize_multiple(cls, urls: List[str]) -> Dict[str, Dict]:
        """
        Categorize multiple URLs

        Args:
            urls: List of URLs to categorize

        Returns:
            Dict mapping URL to categorization result
        """
        return {url: cls.categorize_url(url) for url in urls}

    @classmethod
    def filter_by_category(cls, categorizations: Dict[str, Dict], category: str) -> List[str]:
        """
        Filter URLs by category

        Args:
            categorizations: Result from categorize_multiple
            category: Category name to filter by

        Returns:
            List of URLs in that category
        """
        result = []
        for url, cat_info in categorizations.items():
            if any(c['name'] == category for c in cat_info['categories']):
                result.append(url)
        return result

    @classmethod
    def get_sensitive_urls(cls, categorizations: Dict[str, Dict]) -> List[str]:
        """
        Get all URLs marked as sensitive

        Args:
            categorizations: Result from categorize_multiple

        Returns:
            List of sensitive URLs
        """
        return [url for url, info in categorizations.items() if info['is_sensitive']]


def categorize_endpoint(url: str) -> Dict:
    """
    Convenience function to categorize a single endpoint

    Args:
        url: URL to categorize

    Returns:
        Categorization result
    """
    return EndpointCategorizer.categorize_url(url)


def categorize_endpoints(urls: List[str]) -> Dict[str, Dict]:
    """
    Convenience function to categorize multiple endpoints

    Args:
        urls: List of URLs to categorize

    Returns:
        Dict mapping URL to categorization result
    """
    return EndpointCategorizer.categorize_multiple(urls)
