"""
JavaScript File Analyzer
Checks if JS files are accessible and scans for secrets/sensitive information
"""

import logging
import re
import requests
from typing import Dict, List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class JSFileAnalyzer:
    """Analyzer for JavaScript files to detect secrets and check accessibility"""

    # Regex patterns for detecting secrets
    SECRET_PATTERNS = {
        'aws_access_key': r'(?i)aws_access_key_id[\'"\s]*[:=][\'"\s]*([A-Z0-9]{20})',
        'aws_secret_key': r'(?i)aws_secret_access_key[\'"\s]*[:=][\'"\s]*([A-Za-z0-9/+=]{40})',
        'google_api_key': r'(?i)AIza[0-9A-Za-z\-_]{35}',
        'google_oauth': r'(?i)[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'firebase': r'(?i)AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'github_token': r'(?i)gh[pousr]_[A-Za-z0-9]{36}',
        'generic_api_key': r'(?i)(?:api[_-]?key|apikey)[\'"\s]*[:=][\'"\s]*([\'"][a-zA-Z0-9_\-]{20,}[\'"]|[a-zA-Z0-9_\-]{20,})',
        'generic_secret': r'(?i)(?:secret|password|passwd|pwd)[\'"\s]*[:=][\'"\s]*([\'"][^\'"\s]{8,}[\'"]|[^\'"\s]{8,})',
        'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*',
        'private_key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        'authorization_bearer': r'(?i)authorization[\'"\s]*:[\'"\s]*Bearer\s+[A-Za-z0-9\-._~+/]+=*',
        'slack_token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24,}',
        'stripe_key': r'(?i)(?:sk|pk)_live_[0-9a-zA-Z]{24,}',
        'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
        'twilio_api_key': r'SK[0-9a-fA-F]{32}',
        'square_token': r'sq0atp-[0-9A-Za-z\-_]{22}',
        'paypal_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        'heroku_api_key': r'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
    }

    # Suspicious keywords
    SUSPICIOUS_KEYWORDS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'access_token', 'auth_token', 'private_key', 'client_secret',
        'encryption_key', 'database_password', 'db_password', 'admin_pass'
    ]

    def __init__(self, timeout: int = 10, max_workers: int = 10):
        """
        Initialize JS file analyzer

        Args:
            timeout: HTTP request timeout
            max_workers: Maximum concurrent workers
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def check_accessibility(self, url: str) -> Dict:
        """
        Check if JS file is accessible

        Args:
            url: JS file URL

        Returns:
            Dict with status, status_code, content_type, size
        """
        try:
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)

            # If HEAD not supported, try GET with range
            if response.status_code in [405, 404]:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    headers={'Range': 'bytes=0-1024'}  # Only get first 1KB
                )

            is_accessible = response.status_code == 200
            content_type = response.headers.get('Content-Type', '')

            # Verify it's actually a JS file
            is_js = (
                'javascript' in content_type.lower() or
                'application/json' in content_type.lower() or
                url.endswith('.js')
            )

            return {
                'accessible': is_accessible and is_js,
                'status_code': response.status_code,
                'content_type': content_type,
                'size': int(response.headers.get('Content-Length', 0)),
                'is_javascript': is_js
            }

        except Exception as e:
            logger.debug(f"Failed to check {url}: {e}")
            return {
                'accessible': False,
                'status_code': 0,
                'content_type': '',
                'size': 0,
                'is_javascript': False,
                'error': str(e)
            }

    def download_content(self, url: str, max_size: int = 5 * 1024 * 1024) -> str:
        """
        Download JS file content

        Args:
            url: JS file URL
            max_size: Maximum file size to download (default 5MB)

        Returns:
            File content as string
        """
        try:
            response = self.session.get(url, timeout=self.timeout, stream=True)

            if response.status_code != 200:
                return ""

            # Check size
            content_length = int(response.headers.get('Content-Length', 0))
            if content_length > max_size:
                logger.warning(f"File too large ({content_length} bytes): {url}")
                return ""

            # Download with size limit
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > max_size:
                    logger.warning(f"File exceeds max size during download: {url}")
                    break

            return content.decode('utf-8', errors='ignore')

        except Exception as e:
            logger.error(f"Failed to download {url}: {e}")
            return ""

    def scan_for_secrets(self, content: str) -> Dict:
        """
        Scan JS file content for secrets

        Args:
            content: JS file content

        Returns:
            Dict with findings
        """
        findings = {
            'has_secrets': False,
            'secrets_found': [],
            'suspicious_keywords': [],
            'risk_level': 'low'  # low, medium, high
        }

        if not content:
            return findings

        # Check for secret patterns
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings['secrets_found'].append({
                    'type': secret_type,
                    'count': len(matches)
                })
                findings['has_secrets'] = True

        # Check for suspicious keywords
        content_lower = content.lower()
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in content_lower:
                findings['suspicious_keywords'].append(keyword)

        # Determine risk level
        if findings['has_secrets']:
            findings['risk_level'] = 'high'
        elif len(findings['suspicious_keywords']) > 5:
            findings['risk_level'] = 'medium'
        elif findings['suspicious_keywords']:
            findings['risk_level'] = 'low'

        return findings

    def analyze_file(self, url: str, check_content: bool = True) -> Dict:
        """
        Analyze a single JS file

        Args:
            url: JS file URL
            check_content: Whether to download and scan content

        Returns:
            Complete analysis result
        """
        result = {
            'url': url,
            'status': 'inactive',
            'accessible': False,
            'is_javascript': False,
            'secrets': {
                'has_secrets': False,
                'risk_level': 'low'
            }
        }

        # Check accessibility
        access_info = self.check_accessibility(url)
        result.update(access_info)

        if access_info['accessible']:
            result['status'] = 'active'

            # Scan content if requested
            if check_content:
                content = self.download_content(url)
                if content:
                    secrets_info = self.scan_for_secrets(content)
                    result['secrets'] = secrets_info

        return result

    def analyze_multiple(
        self,
        urls: List[str],
        check_content: bool = True,
        sample_size: int = None
    ) -> Dict[str, Dict]:
        """
        Analyze multiple JS files concurrently

        Args:
            urls: List of JS file URLs
            check_content: Whether to scan content
            sample_size: If set, only analyze random sample

        Returns:
            Dict mapping URL to analysis result
        """
        if not urls:
            return {}

        # Sample if requested
        if sample_size and sample_size < len(urls):
            import random
            urls = random.sample(urls, sample_size)
            logger.info(f"Analyzing sample of {sample_size} JS files out of {len(urls)}")

        results = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {
                executor.submit(self.analyze_file, url, check_content): url
                for url in urls
            }

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results[url] = result

                    # Log findings
                    if result.get('secrets', {}).get('has_secrets'):
                        logger.warning(f"SECRETS FOUND in {url}")

                except Exception as e:
                    logger.error(f"Error analyzing {url}: {e}")
                    results[url] = {
                        'url': url,
                        'status': 'error',
                        'error': str(e)
                    }

        # Summary
        active_count = sum(1 for r in results.values() if r.get('status') == 'active')
        secrets_count = sum(1 for r in results.values() if r.get('secrets', {}).get('has_secrets'))

        logger.info(
            f"JS file analysis complete: {len(results)} files, "
            f"{active_count} active, {secrets_count} with secrets"
        )

        return results


def analyze_js_files(
    js_urls: List[str],
    check_content: bool = True,
    sample_size: int = None
) -> Dict[str, Dict]:
    """
    Convenience function to analyze JS files

    Args:
        js_urls: List of JS file URLs
        check_content: Whether to scan content for secrets
        sample_size: Optional sample size for large lists

    Returns:
        Analysis results for each file
    """
    analyzer = JSFileAnalyzer()
    return analyzer.analyze_multiple(js_urls, check_content, sample_size)
