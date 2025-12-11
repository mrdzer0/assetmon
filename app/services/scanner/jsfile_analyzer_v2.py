"""
Enhanced JavaScript File Analyzer v2
Uses entropy-based filtering and improved patterns for lower false positives
"""

import logging
import math
import re
import requests
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class EnhancedJSAnalyzer:
    """Enhanced JS analyzer with entropy-based secret detection"""

    # Entropy threshold for high-confidence secrets
    MIN_ENTROPY = 3.5
    
    # Secret patterns based on secretfinder and industry standards
    # https://github.com/m4ll0k/SecretFinder
    SECRET_PATTERNS = {
        # ===== AWS =====
        'aws_access_key': {
            'pattern': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
            'min_entropy': 3.0,
            'severity': 'critical'
        },
        'aws_secret_key': {
            'pattern': r'(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)["\'\s:=]+([A-Za-z0-9/+=]{40})',
            'min_entropy': 4.0,
            'severity': 'critical'
        },
        'aws_mws_key': {
            'pattern': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'min_entropy': 3.5,
            'severity': 'critical'
        },
        # ===== Google/GCP =====
        'google_api_key': {
            'pattern': r'AIza[0-9A-Za-z\-_]{35}',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        'google_oauth_id': {
            'pattern': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        'google_cloud_key': {
            'pattern': r'(?i)(?:google|gcp|googleapis).*[\'"\s:=]+([a-zA-Z0-9_-]{39})',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        'firebase_url': {
            'pattern': r'.*firebaseio\.com',
            'min_entropy': 0,
            'severity': 'medium'
        },
        'firebase_key': {
            'pattern': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'min_entropy': 4.5,
            'severity': 'high'
        },
        # ===== GitHub =====
        'github_token': {
            'pattern': r'gh[pousr]_[A-Za-z0-9]{36,}',
            'min_entropy': 4.0,
            'severity': 'critical'
        },
        'github_oauth': {
            'pattern': r'gho_[A-Za-z0-9]{36}',
            'min_entropy': 4.0,
            'severity': 'critical'
        },
        'github_app_token': {
            'pattern': r'(?:ghu|ghs)_[A-Za-z0-9]{36}',
            'min_entropy': 4.0,
            'severity': 'critical'
        },
        # ===== Stripe =====
        'stripe_secret': {
            'pattern': r'sk_live_[0-9a-zA-Z]{24,}',
            'min_entropy': 4.0,
            'severity': 'critical'
        },
        'stripe_publishable': {
            'pattern': r'pk_live_[0-9a-zA-Z]{24,}',
            'min_entropy': 4.0,
            'severity': 'low'
        },
        'stripe_restricted': {
            'pattern': r'rk_live_[0-9a-zA-Z]{24,}',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        # ===== Slack =====
        'slack_token': {
            'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}(?:-[0-9]{10,13})?-[a-zA-Z0-9]{24,}',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        'slack_webhook': {
            'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            'min_entropy': 3.5,
            'severity': 'high'
        },
        # ===== PayPal =====
        'paypal_braintree': {
            'pattern': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'min_entropy': 4.0,
            'severity': 'critical'
        },
        # ===== Square =====
        'square_access_token': {
            'pattern': r'sq0atp-[0-9A-Za-z\-_]{22}',
            'min_entropy': 4.0,
            'severity': 'critical'
        },
        'square_oauth_secret': {
            'pattern': r'sq0csp-[0-9A-Za-z\-_]{43}',
            'min_entropy': 4.0,
            'severity': 'critical'
        },
        # ===== Twilio =====
        'twilio_api_key': {
            'pattern': r'SK[0-9a-fA-F]{32}',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        'twilio_account_sid': {
            'pattern': r'AC[a-zA-Z0-9_\-]{32}',
            'min_entropy': 3.5,
            'severity': 'medium'
        },
        # ===== SendGrid =====
        'sendgrid_api_key': {
            'pattern': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
            'min_entropy': 4.5,
            'severity': 'high'
        },
        # ===== Mailgun =====
        'mailgun_api_key': {
            'pattern': r'key-[0-9a-zA-Z]{32}',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        # ===== Mailchimp =====
        'mailchimp_api_key': {
            'pattern': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        # ===== Heroku =====
        'heroku_api_key': {
            'pattern': r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            'min_entropy': 3.5,
            'severity': 'high'
        },
        # ===== Discord =====
        'discord_token': {
            'pattern': r'(?:mfa\.[a-z0-9_-]{20,})|(?:[a-z0-9_-]{23,28}\.[a-z0-9_-]{6,7}\.[a-z0-9_-]{27})',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        'discord_webhook': {
            'pattern': r'https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
            'min_entropy': 3.5,
            'severity': 'high'
        },
        # ===== Telegram =====
        'telegram_bot_token': {
            'pattern': r'[0-9]+:AA[0-9A-Za-z_-]{33}',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        # ===== Facebook =====
        'facebook_access_token': {
            'pattern': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        'facebook_oauth': {
            'pattern': r'[fF][aA][cC][eE][bB][oO][oO][kK].*[\'"][0-9a-f]{32}[\'"]',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        # ===== Twitter =====
        'twitter_oauth': {
            'pattern': r'[tT][wW][iI][tT][tT][eE][rR].*[\'"][0-9a-zA-Z]{35,44}[\'"]',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        'twitter_bearer': {
            'pattern': r'AAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%-]+',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        # ===== Azure =====
        'azure_storage_key': {
            'pattern': r'(?i)AccountKey=[a-zA-Z0-9+/=]{88}',
            'min_entropy': 4.5,
            'severity': 'critical'
        },
        # ===== DigitalOcean =====
        'digitalocean_token': {
            'pattern': r'dop_v1_[a-f0-9]{64}',
            'min_entropy': 4.5,
            'severity': 'critical'
        },
        # ===== NPM =====
        'npm_token': {
            'pattern': r'npm_[A-Za-z0-9]{36}',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        # ===== PyPI =====
        'pypi_token': {
            'pattern': r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}',
            'min_entropy': 4.5,
            'severity': 'high'
        },
        # ===== JWT =====
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+',
            'min_entropy': 4.5,
            'severity': 'high'
        },
        # ===== Private Keys =====
        'private_key_rsa': {
            'pattern': r'-----BEGIN RSA PRIVATE KEY-----',
            'min_entropy': 0,
            'severity': 'critical'
        },
        'private_key_openssh': {
            'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'min_entropy': 0,
            'severity': 'critical'
        },
        'private_key_ec': {
            'pattern': r'-----BEGIN EC PRIVATE KEY-----',
            'min_entropy': 0,
            'severity': 'critical'
        },
        'private_key_pgp': {
            'pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'min_entropy': 0,
            'severity': 'critical'
        },
        # ===== Generic High-Value (strict entropy) =====
        'generic_api_key': {
            'pattern': r'(?i)(?:api[_-]?key|apikey)["\'\s:=]+["\']?([a-zA-Z0-9_\-]{32,64})["\']?',
            'min_entropy': 4.5,
            'severity': 'medium'
        },
        'generic_secret': {
            'pattern': r'(?i)(?:client_secret|app_secret)["\'\s:=]+["\']?([a-zA-Z0-9_\-]{20,64})["\']?',
            'min_entropy': 4.5,
            'severity': 'medium'
        },
        'bearer_token': {
            'pattern': r'(?i)bearer\s+([a-zA-Z0-9_\-.~+/]{20,}=*)',
            'min_entropy': 4.0,
            'severity': 'high'
        },
        'authorization_basic': {
            'pattern': r'(?i)basic\s+([a-zA-Z0-9+/]{20,}=*)',
            'min_entropy': 3.5,
            'severity': 'high'
        },
    }

    # Patterns to EXCLUDE (false positives)
    EXCLUDE_PATTERNS = [
        r'example\.com',
        r'localhost',
        r'127\.0\.0\.1',
        r'0\.0\.0\.0',
        r'placeholder',
        r'your[_-]?api[_-]?key',
        r'xxx+',
        r'test[_-]?key',
        r'demo[_-]?key',
        r'sample',
        r'dummy',
        r'fake',
    ]

    def __init__(self, timeout: int = 10, max_workers: int = 10):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in set(data):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        
        return entropy

    def is_excluded(self, value: str) -> bool:
        """Check if value matches exclusion patterns (false positives)"""
        value_lower = value.lower()
        for pattern in self.EXCLUDE_PATTERNS:
            if re.search(pattern, value_lower):
                return True
        return False

    def download_content(self, url: str, max_size: int = 5 * 1024 * 1024) -> str:
        """Download JS file content"""
        try:
            response = self.session.get(url, timeout=self.timeout, stream=True)
            
            if response.status_code != 200:
                return ""
            
            content_length = int(response.headers.get('Content-Length', 0))
            if content_length > max_size:
                logger.warning(f"File too large ({content_length} bytes): {url}")
                return ""
            
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > max_size:
                    break
            
            return content.decode('utf-8', errors='ignore')
        
        except Exception as e:
            logger.error(f"Failed to download {url}: {e}")
            return ""

    def scan_for_secrets(self, content: str) -> Dict:
        """
        Scan content for secrets with entropy-based validation
        
        Returns dict with:
        - has_secrets: bool
        - secrets_found: list of confirmed secrets
        - risk_level: high/medium/low
        """
        findings = {
            'has_secrets': False,
            'secrets_found': [],
            'risk_level': 'low',
            'highest_severity': 'low'
        }
        
        if not content:
            return findings
        
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        
        for secret_type, config in self.SECRET_PATTERNS.items():
            pattern = config['pattern']
            min_entropy = config['min_entropy']
            severity = config['severity']
            
            matches = re.findall(pattern, content)
            
            for match in matches:
                # Get the actual secret value (might be in a group)
                secret_value = match if isinstance(match, str) else match[0] if match else ""
                
                if not secret_value or len(secret_value) < 10:
                    continue
                
                # Check exclusions
                if self.is_excluded(secret_value):
                    continue
                
                # Entropy check
                entropy = self.calculate_entropy(secret_value)
                if entropy < min_entropy:
                    continue
                
                # Valid secret found!
                findings['has_secrets'] = True
                findings['secrets_found'].append({
                    'type': secret_type,
                    'severity': severity,
                    'entropy': round(entropy, 2),
                    'length': len(secret_value),
                    'value': secret_value  # Full value, no masking
                })
                
                # Update highest severity
                if severity_order.get(severity, 0) > severity_order.get(findings['highest_severity'], 0):
                    findings['highest_severity'] = severity
        
        # Set risk level based on highest severity
        if findings['highest_severity'] in ['critical', 'high']:
            findings['risk_level'] = 'high'
        elif findings['highest_severity'] == 'medium':
            findings['risk_level'] = 'medium'
        
        return findings

    def extract_endpoints(self, content: str) -> List[str]:
        """
        Extract potential API endpoints from JS content
        Based on LinkFinder approach: https://github.com/GerbenJavado/LinkFinder
        """
        endpoints = set()
        
        # LinkFinder-style regex patterns (4 categories)
        patterns = [
            # 1. Full URLs (https://example.com/*)
            r'["\']((https?:)?//[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z0-9\-\.]+[^\s"\'<>]*)["\']',
            
            # 2. Absolute paths (/path/to/resource)
            r'["\'](/[a-zA-Z0-9_\-./]+)["\']',
            
            # 3. Relative paths with extension (path/file.ext, ../path/file)
            r'["\']([a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)*\.[a-zA-Z]{2,4})["\']',
            
            # 4. API-specific patterns
            r'["\'](/api/[^\s"\'<>]+)["\']',
            r'["\'](/v[0-9]+/[^\s"\'<>]+)["\']',
            r'["\'](/graphql[^\s"\'<>]*)["\']',
            r'["\'](/rest/[^\s"\'<>]+)["\']',
            r'["\'](/oauth[^\s"\'<>]*)["\']',
            r'["\'](/auth[^\s"\'<>]*)["\']',
            r'["\'](/login[^\s"\'<>]*)["\']',
            r'["\'](/admin[^\s"\'<>]*)["\']',
            r'["\'](/config[^\s"\'<>]*)["\']',
            r'["\'](/settings[^\s"\'<>]*)["\']',
            
            # 5. JavaScript function calls (fetch, axios, etc.)
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest\s*\(\s*\)\s*\.open\s*\([^,]+,\s*["\']([^"\']+)["\']',
            r'\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*["\']([^"\']+)["\']',
            r'url\s*[:=]\s*["\']([^"\']+)["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
            r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
            r'href\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        # Exclusion patterns (false positives)
        exclude_patterns = [
            r'^data:',           # Data URLs
            r'^javascript:',     # JavaScript URLs
            r'^#',               # Anchors
            r'^\.$',             # Current dir
            r'^\.\.$',           # Parent dir
            r'\.map$',           # Source maps
            r'\.png$', r'\.jpg$', r'\.jpeg$', r'\.gif$', r'\.svg$', r'\.ico$',  # Images
            r'\.css$',           # Stylesheets
            r'\.woff', r'\.ttf', r'\.eot',  # Fonts
            r'node_modules',     # Node modules
            r'webpack',          # Webpack internals
        ]
        
        for pattern in patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    url = match[0] if isinstance(match, tuple) else match
                    
                    if not url or len(url) < 3:
                        continue
                    
                    # Apply exclusions
                    excluded = False
                    for exc in exclude_patterns:
                        if re.search(exc, url, re.IGNORECASE):
                            excluded = True
                            break
                    
                    if not excluded:
                        endpoints.add(url)
            except re.error:
                continue
        
        return list(endpoints)[:200]  # Limit to 200

    def analyze_file(self, url: str, check_content: bool = True) -> Dict:
        """Analyze a single JS file"""
        result = {
            'url': url,
            'status': 'pending',
            'accessible': False,
            'secrets': {'has_secrets': False, 'risk_level': 'low'},
            'endpoints': []
        }
        
        if not check_content:
            return result
        
        content = self.download_content(url)
        if not content:
            result['status'] = 'inaccessible'
            return result
        
        result['accessible'] = True
        result['status'] = 'analyzed'
        result['secrets'] = self.scan_for_secrets(content)
        result['endpoints'] = self.extract_endpoints(content)
        
        return result

    def analyze_multiple(
        self,
        urls: List[str],
        check_content: bool = True,
        sample_size: Optional[int] = None
    ) -> Dict[str, Dict]:
        """Analyze multiple JS files concurrently"""
        if not urls:
            return {}
        
        if sample_size and sample_size < len(urls):
            import random
            urls = random.sample(urls, sample_size)
            logger.info(f"Analyzing sample of {sample_size} JS files")
        
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
                    
                    if result.get('secrets', {}).get('has_secrets'):
                        logger.warning(f"SECRETS FOUND in {url}")
                
                except Exception as e:
                    logger.error(f"Error analyzing {url}: {e}")
                    results[url] = {'url': url, 'status': 'error', 'error': str(e)}
        
        # Summary
        secrets_count = sum(1 for r in results.values() if r.get('secrets', {}).get('has_secrets'))
        logger.info(f"JS analysis complete: {len(results)} files, {secrets_count} with secrets")
        
        return results


def analyze_js_files_v2(
    js_urls: List[str],
    check_content: bool = True,
    sample_size: Optional[int] = None
) -> Dict[str, Dict]:
    """
    Convenience function to analyze JS files with enhanced analyzer
    """
    analyzer = EnhancedJSAnalyzer()
    return analyzer.analyze_multiple(js_urls, check_content, sample_size)
