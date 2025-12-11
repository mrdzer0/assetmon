"""
Unit Tests for Enhanced JS File Analyzer v2
"""

import pytest
from app.services.scanner.jsfile_analyzer_v2 import EnhancedJSAnalyzer


class TestEntropyCalculation:
    """Test Shannon entropy calculation"""
    
    def test_low_entropy_repeated_chars(self):
        """Repeated characters should have 0 entropy"""
        analyzer = EnhancedJSAnalyzer()
        assert analyzer.calculate_entropy("aaaaaaaaaa") == 0.0
    
    def test_high_entropy_random_string(self):
        """Random string should have high entropy"""
        analyzer = EnhancedJSAnalyzer()
        entropy = analyzer.calculate_entropy("aB3xK9mZ2pQ7nL5w")
        assert entropy >= 3.5
    
    def test_empty_string(self):
        """Empty string should return 0"""
        analyzer = EnhancedJSAnalyzer()
        assert analyzer.calculate_entropy("") == 0.0


class TestExclusionPatterns:
    """Test false positive exclusions"""
    
    def test_excludes_placeholder(self):
        analyzer = EnhancedJSAnalyzer()
        assert analyzer.is_excluded("your-api-key-here") == True
    
    def test_excludes_test_key(self):
        analyzer = EnhancedJSAnalyzer()
        assert analyzer.is_excluded("test_key_12345") == True
    
    def test_excludes_localhost(self):
        analyzer = EnhancedJSAnalyzer()
        assert analyzer.is_excluded("http://localhost:3000") == True
    
    def test_allows_real_key(self):
        analyzer = EnhancedJSAnalyzer()
        assert analyzer.is_excluded("AKIAIOSFODNN7EXAMPLE") == False


class TestSecretDetection:
    """Test secret pattern detection"""
    
    def test_detects_aws_access_key(self):
        analyzer = EnhancedJSAnalyzer()
        content = 'const key = "AKIAIOSFODNN7EXAMPLE";'
        result = analyzer.scan_for_secrets(content)
        assert result['has_secrets'] == True
        assert any(s['type'] == 'aws_access_key' for s in result['secrets_found'])
    
    def test_detects_stripe_live_key(self):
        analyzer = EnhancedJSAnalyzer()
        content = 'const stripe = "sk_live_abcdefghijklmnopqrstuvwx";'
        result = analyzer.scan_for_secrets(content)
        assert result['has_secrets'] == True
        assert any(s['type'] == 'stripe_secret' for s in result['secrets_found'])
    
    def test_detects_private_key(self):
        analyzer = EnhancedJSAnalyzer()
        content = '-----BEGIN RSA PRIVATE KEY-----'
        result = analyzer.scan_for_secrets(content)
        assert result['has_secrets'] == True
    
    def test_ignores_placeholder_api_key(self):
        analyzer = EnhancedJSAnalyzer()
        content = 'const key = "your-api-key-here";'
        result = analyzer.scan_for_secrets(content)
        assert result['has_secrets'] == False
    
    def test_empty_content(self):
        analyzer = EnhancedJSAnalyzer()
        result = analyzer.scan_for_secrets("")
        assert result['has_secrets'] == False


class TestEndpointExtraction:
    """Test endpoint extraction from JS content"""
    
    def test_extracts_api_endpoints(self):
        analyzer = EnhancedJSAnalyzer()
        content = 'fetch("/api/users");'
        endpoints = analyzer.extract_endpoints(content)
        assert "/api/users" in endpoints
    
    def test_extracts_full_urls(self):
        analyzer = EnhancedJSAnalyzer()
        content = 'const url = "https://api.example.com/data";'
        endpoints = analyzer.extract_endpoints(content)
        assert "https://api.example.com/data" in endpoints
    
    def test_excludes_image_files(self):
        analyzer = EnhancedJSAnalyzer()
        content = 'const img = "/static/logo.png";'
        endpoints = analyzer.extract_endpoints(content)
        assert not any(ep.endswith('.png') for ep in endpoints)


class TestPatternCoverage:
    """Test that all major services are covered"""
    
    def test_pattern_count(self):
        analyzer = EnhancedJSAnalyzer()
        assert len(analyzer.SECRET_PATTERNS) >= 40


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
