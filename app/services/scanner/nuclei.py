"""
Nuclei vulnerability scanner integration
Runs Nuclei scans with customizable configuration
"""

import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime
from typing import Dict, List, Optional

from app.config import settings

logger = logging.getLogger(__name__)


class NucleiScanner:
    """
    Nuclei vulnerability scanner integration
    """
    
    # Default configuration
    DEFAULT_CONFIG = {
        "enabled": False,
        "severity": ["critical", "high"],
        "tags": [],  # Empty = all tags
        "exclude_tags": ["dos", "fuzz", "intrusive"],
        "rate_limit": 150,
        "concurrency": 25,
        "timeout": 5,
        "scan_alive_only": True,
        "max_host_error": 30
    }
    
    def __init__(self, project_id: int, config: Optional[Dict] = None):
        """
        Initialize Nuclei scanner
        
        Args:
            project_id: Project ID for logging
            config: Nuclei configuration from project settings
        """
        self.project_id = project_id
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}
        self.nuclei_path = settings.nuclei_path
        self.templates_path = settings.nuclei_templates_path
        
    def is_available(self) -> bool:
        """Check if nuclei is available"""
        import shutil
        return shutil.which(self.nuclei_path) is not None
    
    def scan(self, targets: List[str]) -> Dict:
        """
        Run Nuclei scan on targets
        
        Args:
            targets: List of URLs/hosts to scan
            
        Returns:
            Dict with findings, stats, and metadata
        """
        if not self.is_available():
            logger.error("Nuclei is not available")
            return {"findings": [], "stats": {}, "error": "Nuclei not found"}
        
        if not targets:
            logger.warning("No targets provided for Nuclei scan")
            return {"findings": [], "stats": {}, "error": "No targets"}
        
        if not self.config.get("enabled", False):
            logger.info("Nuclei scan is disabled for project %s", self.project_id)
            return {"findings": [], "stats": {}, "skipped": True}
        
        logger.info("Starting Nuclei scan for project %s with %d targets", 
                   self.project_id, len(targets))
        
        findings = []
        
        try:
            # Create temp files for targets and output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
                tf.write('\n'.join(targets))
                targets_file = tf.name
            
            output_file = tempfile.mktemp(suffix='.json')
            
            try:
                # Build and run command
                cmd = self._build_command(targets_file, output_file)
                logger.info("Running Nuclei command: %s", ' '.join(cmd))
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=settings.scan_timeout
                )
                
                # Debug logging
                logger.info("Nuclei exit code: %d", result.returncode)
                if result.stdout:
                    logger.info("Nuclei stdout: %s", result.stdout[:500])
                if result.stderr:
                    logger.info("Nuclei stderr: %s", result.stderr[:500])
                
                # Check if output file was created
                if os.path.exists(output_file):
                    file_size = os.path.getsize(output_file)
                    logger.info("Nuclei output file exists, size: %d bytes", file_size)
                else:
                    logger.warning("Nuclei output file was not created")
                
                # Parse results
                findings = self._parse_results(output_file)
                
            finally:
                # Clean up temp files
                if os.path.exists(targets_file):
                    os.unlink(targets_file)
                if os.path.exists(output_file):
                    os.unlink(output_file)
                    
        except subprocess.TimeoutExpired:
            logger.error("Nuclei scan timed out for project %s", self.project_id)
            return {"findings": [], "stats": {}, "error": "Scan timed out"}
        except Exception as e:
            logger.error("Nuclei scan failed for project %s: %s", self.project_id, str(e))
            return {"findings": [], "stats": {}, "error": str(e)}
        
        # Calculate stats
        stats = self._calculate_stats(findings)
        
        logger.info("Nuclei scan completed for project %s: %d findings", 
                   self.project_id, len(findings))
        
        return {
            "findings": findings,
            "stats": stats,
            "scanned_at": datetime.utcnow().isoformat(),
            "targets_count": len(targets)
        }
    
    def _build_command(self, targets_file: str, output_file: str) -> List[str]:
        """
        Build nuclei command with configured options
        
        Args:
            targets_file: Path to file containing targets
            output_file: Path for JSON output
            
        Returns:
            Command as list of strings
        """
        cmd = [
            self.nuclei_path,
            "-l", targets_file,
            "-jsonl",  # Write output in JSONL format
            "-jle", output_file,  # JSON lines export file
            "-silent",
            "-nc",  # No color
        ]
        
        # Severity filter
        severity = self.config.get("severity", [])
        if severity:
            cmd.extend(["-s", ",".join(severity)])
        
        # Tags to include
        tags = self.config.get("tags", [])
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        # Tags to exclude
        exclude_tags = self.config.get("exclude_tags", [])
        if exclude_tags:
            cmd.extend(["-etags", ",".join(exclude_tags)])
        
        # Rate limiting
        rate_limit = self.config.get("rate_limit", 150)
        cmd.extend(["-rl", str(rate_limit)])
        
        # Concurrency
        concurrency = self.config.get("concurrency", 25)
        cmd.extend(["-c", str(concurrency)])
        
        # Timeout per request
        timeout = self.config.get("timeout", 5)
        cmd.extend(["-timeout", str(timeout)])
        
        # Max host errors
        max_host_error = self.config.get("max_host_error", 30)
        cmd.extend(["-mhe", str(max_host_error)])
        
        # Custom templates path
        if self.templates_path:
            cmd.extend(["-t", self.templates_path])
        
        return cmd
    
    def _parse_results(self, output_file: str) -> List[Dict]:
        """
        Parse nuclei JSON output into findings
        
        Args:
            output_file: Path to nuclei JSON output
            
        Returns:
            List of parsed findings
        """
        findings = []
        
        if not os.path.exists(output_file):
            return findings
        
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        result = json.loads(line)
                        finding = self._normalize_finding(result)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse nuclei result line: %s", line[:100])
        except Exception as e:
            logger.error("Failed to read nuclei output: %s", str(e))
        
        return findings
    
    def _normalize_finding(self, result: Dict) -> Optional[Dict]:
        """
        Normalize a nuclei result into a standard finding format
        
        Args:
            result: Raw nuclei JSON result
            
        Returns:
            Normalized finding dict
        """
        try:
            template_info = result.get("info", {})
            
            finding = {
                "template_id": result.get("template-id", result.get("templateID", "")),
                "template_name": template_info.get("name", ""),
                "severity": template_info.get("severity", "unknown"),
                "host": result.get("host", ""),
                "matched_at": result.get("matched-at", result.get("matched", "")),
                "type": result.get("type", ""),
                "ip": result.get("ip", ""),
                "timestamp": result.get("timestamp", datetime.utcnow().isoformat()),
                "matcher_name": result.get("matcher-name", result.get("matcher_name", "")),
                "extracted_results": result.get("extracted-results", []),
                "curl_command": result.get("curl-command", ""),
                "description": template_info.get("description", ""),
                "reference": template_info.get("reference", []),
                "tags": template_info.get("tags", []),
                "source": "nuclei"
            }
            
            return finding
            
        except Exception as e:
            logger.warning("Failed to normalize nuclei finding: %s", str(e))
            return None
    
    def _calculate_stats(self, findings: List[Dict]) -> Dict:
        """
        Calculate statistics from findings
        
        Args:
            findings: List of findings
            
        Returns:
            Stats dict
        """
        stats = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "unknown": 0,
            "by_template": {},
            "by_host": {}
        }
        
        for finding in findings:
            severity = finding.get("severity", "unknown").lower()
            if severity in stats:
                stats[severity] += 1
            else:
                stats["unknown"] += 1
            
            # Count by template
            template_id = finding.get("template_id", "unknown")
            stats["by_template"][template_id] = stats["by_template"].get(template_id, 0) + 1
            
            # Count by host
            host = finding.get("host", "unknown")
            stats["by_host"][host] = stats["by_host"].get(host, 0) + 1
        
        return stats


def get_default_nuclei_config() -> Dict:
    """Get default nuclei configuration for new projects"""
    return NucleiScanner.DEFAULT_CONFIG.copy()
