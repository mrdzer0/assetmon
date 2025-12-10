"""
Port Scanner Module
Scans for open web service ports using naabu and probes them with httpx.
Focus on non-standard ports (excluding 80/443 which are already scanned).
"""

import logging
import subprocess
import tempfile
import json
import os
import shutil
from typing import List, Dict, Optional, Set
from datetime import datetime

from app.config import settings

logger = logging.getLogger(__name__)


class PortScanner:
    """
    Scans subdomains for open web ports using naabu,
    then probes discovered ports with httpx.
    """
    
    def __init__(self, ports: Optional[str] = None, screenshot_enabled: bool = False, screenshot_dir: Optional[str] = None):
        """
        Initialize port scanner
        
        Args:
            ports: Comma-separated port list (defaults to config.web_ports)
            screenshot_enabled: Whether to capture screenshots with httpx
            screenshot_dir: Directory to save screenshots (required if screenshot_enabled)
        """
        self.ports = ports or settings.web_ports
        self.screenshot_enabled = screenshot_enabled
        self.screenshot_dir = screenshot_dir
        self.results: Dict[str, List[Dict]] = {}  # subdomain -> list of port findings
        self.ip_to_subdomain: Dict[str, List[str]] = {}  # IP -> list of subdomains
        self.stats = {
            "total_targets": 0,
            "open_ports_found": 0,
            "http_services_found": 0,
            "screenshots_captured": 0,
            "failed": 0
        }
        
        # Create screenshot directory if needed and cleanup old screenshots
        if self.screenshot_enabled and self.screenshot_dir:
            if os.path.exists(self.screenshot_dir):
                # Clean up old screenshots to prevent storage bloat
                old_files = [f for f in os.listdir(self.screenshot_dir) if f.endswith('.png')]
                for old_file in old_files:
                    try:
                        os.remove(os.path.join(self.screenshot_dir, old_file))
                    except Exception as e:
                        logger.warning(f"Failed to remove old screenshot {old_file}: {e}")
                if old_files:
                    logger.info(f"Cleaned up {len(old_files)} old screenshots")
            os.makedirs(self.screenshot_dir, exist_ok=True)
            logger.info(f"Screenshots will be saved to: {self.screenshot_dir}")
    
    def scan(self, subdomains: List[str], dns_records: Dict[str, Dict]) -> Dict:
        """
        Scan subdomains for open ports
        
        Args:
            subdomains: List of subdomains to scan
            dns_records: DNS records dict (subdomain -> {a: [], cname: []})
        
        Returns:
            Scan results with open ports and HTTP service info
        """
        # Filter subdomains that have A or CNAME records
        targets, self.ip_to_subdomain = self._filter_resolvable(subdomains, dns_records)
        self.stats["total_targets"] = len(targets)
        
        if not targets:
            logger.warning("No subdomains with A/CNAME records to scan")
            return self._build_result()
        
        logger.info(f"Port scanning {len(targets)} targets on ports: {self.ports}")
        
        # Step 1: Run naabu to find open ports
        open_ports = self._run_naabu(targets)
        
        if not open_ports:
            logger.info("No open ports found")
            return self._build_result()
        
        self.stats["open_ports_found"] = sum(len(ports) for ports in open_ports.values())
        
        # Step 2: Probe each open port with httpx
        http_results = self._probe_with_httpx(open_ports, targets)
        self.stats["http_services_found"] = len(http_results)
        
        self.results = http_results
        
        return self._build_result()
    
    def _filter_resolvable(self, subdomains: List[str], dns_records: Dict[str, Dict]) -> tuple:
        """Filter subdomains that have A or CNAME records and build IP->subdomain mapping"""
        resolvable = []
        ip_to_subdomain: Dict[str, List[str]] = {}
        
        for sub in subdomains:
            if sub in dns_records:
                records = dns_records[sub]
                a_records = records.get("a", records.get("A", []))
                cname_records = records.get("cname", records.get("CNAME", []))
                
                if a_records or cname_records:
                    resolvable.append(sub)
                    # Build IP to subdomain mapping
                    for ip in a_records:
                        if ip not in ip_to_subdomain:
                            ip_to_subdomain[ip] = []
                        if sub not in ip_to_subdomain[ip]:
                            ip_to_subdomain[ip].append(sub)
        
        logger.info(f"Filtered {len(resolvable)}/{len(subdomains)} subdomains with A/CNAME records")
        return resolvable, ip_to_subdomain
    
    def _run_naabu(self, targets: List[str]) -> Dict[str, List[int]]:
        """
        Run naabu port scan
        
        Returns:
            Dict mapping subdomain to list of open ports
        """
        open_ports: Dict[str, List[int]] = {}
        
        try:
            # Create temp file with targets
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for target in targets:
                    f.write(f"{target}\n")
                targets_file = f.name
            
            # Run naabu
            cmd = [
                settings.naabu_path,
                "-list", targets_file,
                "-p", self.ports,
                "-json",
                "-silent",
                "-rate", "500"  # Rate limit to avoid issues
            ]
            
            logger.info(f"Running naabu: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.tool_timeout
            )
            
            # Parse JSON lines output
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    host = data.get("host", data.get("ip", ""))
                    port = data.get("port")
                    
                    if host and port:
                        if host not in open_ports:
                            open_ports[host] = []
                        open_ports[host].append(port)
                        logger.debug(f"Found open port: {host}:{port}")
                        
                except json.JSONDecodeError:
                    continue
            
            logger.info(f"Naabu found {sum(len(p) for p in open_ports.values())} open ports on {len(open_ports)} hosts")
            
        except subprocess.TimeoutExpired:
            logger.error("Naabu scan timed out")
            self.stats["failed"] += 1
        except Exception as e:
            logger.error(f"Naabu scan failed: {e}")
            self.stats["failed"] += 1
        
        return open_ports
    
    def _probe_with_httpx(self, open_ports: Dict[str, List[int]], targets: List[str]) -> Dict[str, List[Dict]]:
        """
        Probe open ports with httpx to get HTTP service info
        
        Args:
            open_ports: Dict mapping host (IP or subdomain) to list of open ports
            targets: List of original subdomain names
        
        Returns:
            Dict mapping subdomain to list of HTTP service findings
        """
        results: Dict[str, List[Dict]] = {}
        
        # Build list of URLs to probe - use subdomains where possible
        urls_to_probe = []
        url_to_subdomain = {}  # Map URL to original subdomain
        
        for host, ports in open_ports.items():
            # Try to find the subdomain(s) for this host/IP
            subdomains = self.ip_to_subdomain.get(host, [])
            
            # If host is an IP and we have subdomains, use the subdomain
            # If host is already a subdomain, use it directly
            hosts_to_probe = subdomains if subdomains else [host]
            
            for probe_host in hosts_to_probe:
                for port in ports:
                    # Try HTTPS for common SSL ports
                    if port in [443, 8443, 9443, 3443, 4443]:
                        url = f"https://{probe_host}:{port}"
                    else:
                        url = f"http://{probe_host}:{port}"
                    
                    urls_to_probe.append(url)
                    url_to_subdomain[url] = probe_host
        
        if not urls_to_probe:
            return results
        
        try:
            # Create temp file with URLs
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for url in urls_to_probe:
                    f.write(f"{url}\n")
                urls_file = f.name
            
            # Create temp dir for screenshots if enabled
            screenshot_temp_dir = None
            if self.screenshot_enabled and self.screenshot_dir:
                screenshot_temp_dir = tempfile.mkdtemp(prefix="httpx_screenshots_")
            
            # Run httpx
            cmd = [
                settings.httpx_path,
                "-list", urls_file,
                "-json",
                "-silent",
                "-title",
                "-status-code",
                "-tech-detect",
                "-timeout", "15",
                "-threads", "10"
            ]
            
            # Add screenshot flags if enabled
            if screenshot_temp_dir:
                cmd.extend(["-screenshot", "-srd", screenshot_temp_dir])
                logger.info(f"Screenshot capture enabled, temp dir: {screenshot_temp_dir}")
            
            logger.info(f"Probing {len(urls_to_probe)} URLs with httpx" + (" (with screenshots)" if screenshot_temp_dir else ""))
            
            scan_timestamp = datetime.utcnow().isoformat()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.tool_timeout * 2 if screenshot_temp_dir else settings.tool_timeout  # More time for screenshots
            )
            
            # Parse results
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    host = data.get("host", "")
                    port = data.get("port", 0)
                    status_code = data.get("status_code", data.get("status-code", 0))
                    title = data.get("title", "")
                    technologies = data.get("tech", data.get("technologies", []))
                    screenshot_path_temp = data.get("screenshot_path", data.get("screenshot", ""))
                    
                    if not host:
                        # Extract host from URL
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        host = parsed.netloc.split(':')[0]
                        if parsed.port:
                            port = parsed.port
                    
                    # Get the original subdomain for this URL/host
                    subdomain = url_to_subdomain.get(url, host)
                    
                    # Handle screenshot - copy to permanent location only if file has content
                    screenshot_web_path = ""
                    if screenshot_path_temp and os.path.exists(screenshot_path_temp) and self.screenshot_dir:
                        # Check if screenshot file has actual content (not empty/0 bytes)
                        file_size = os.path.getsize(screenshot_path_temp)
                        if file_size > 0:
                            # Create unique filename: subdomain_port_timestamp.png
                            safe_subdomain = subdomain.replace(".", "_").replace(":", "_")
                            screenshot_filename = f"{safe_subdomain}_{port}.png"
                            screenshot_dest = os.path.join(self.screenshot_dir, screenshot_filename)
                            
                            try:
                                shutil.copy2(screenshot_path_temp, screenshot_dest)
                                # Web-accessible path (relative to static)
                                screenshot_web_path = f"/static/screenshots/ports/{os.path.basename(self.screenshot_dir)}/{screenshot_filename}"
                                self.stats["screenshots_captured"] = self.stats.get("screenshots_captured", 0) + 1
                                logger.info(f"Screenshot saved: {screenshot_filename} ({file_size} bytes)")
                            except Exception as e:
                                logger.warning(f"Failed to copy screenshot: {e}")
                        else:
                            logger.debug(f"Skipping empty screenshot for {subdomain}:{port}")
                    
                    if host:
                        if host not in results:
                            results[host] = []
                        
                        # Get port description
                        port_info = self._get_port_info(port)
                        
                        results[host].append({
                            "port": port,
                            "port_name": port_info["name"],
                            "port_description": port_info["description"],
                            "url": url,
                            "subdomain": subdomain,
                            "status_code": status_code,
                            "title": title,
                            "technologies": technologies if isinstance(technologies, list) else [],
                            "screenshot": screenshot_web_path,
                            "scan_date": scan_timestamp,
                            "discovered_at": datetime.utcnow().isoformat()
                        })
                        logger.info(f"HTTP service found: {subdomain}:{port} - {title} ({status_code})")
                        
                except json.JSONDecodeError:
                    continue
            
            # Cleanup temp screenshot dir
            if screenshot_temp_dir and os.path.exists(screenshot_temp_dir):
                try:
                    shutil.rmtree(screenshot_temp_dir)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp screenshot dir: {e}")
            
        except subprocess.TimeoutExpired:
            logger.error("httpx probe timed out")
        except Exception as e:
            logger.error(f"httpx probe failed: {e}")
        
        return results
    
    def _get_port_info(self, port: int) -> Dict[str, str]:
        """Get port name and description"""
        port_db = {
            8080: {"name": "HTTP-Proxy", "description": "Common HTTP proxy/alternative port"},
            8443: {"name": "HTTPS-Alt", "description": "Alternative HTTPS port"},
            8000: {"name": "HTTP-Alt", "description": "Python/Django dev server common port"},
            8888: {"name": "HTTP-Alt", "description": "Jupyter/alternative web service port"},
            3000: {"name": "Node.js", "description": "Common Node.js/React dev server port"},
            3443: {"name": "HTTPS-Alt", "description": "Alternative HTTPS port"},
            5000: {"name": "Flask/Dev", "description": "Python Flask/development server port"},
            9000: {"name": "PHP-FPM", "description": "PHP-FPM or SonarQube port"},
            9443: {"name": "HTTPS-Alt", "description": "Alternative HTTPS/management port"},
            4443: {"name": "HTTPS-Alt", "description": "Alternative HTTPS port"},
            2083: {"name": "cPanel", "description": "cPanel SSL port"},
            2087: {"name": "WHM", "description": "WHM (Web Host Manager) SSL port"},
        }
        
        return port_db.get(port, {"name": f"Port-{port}", "description": "Non-standard web service port"})
    
    def _build_result(self) -> Dict:
        """Build final result dictionary"""
        return {
            "port_findings": self.results,
            "stats": self.stats,
            "ports_scanned": self.ports,
            "scan_time": datetime.utcnow().isoformat()
        }
    
    def get_findings_for_events(self) -> List[Dict]:
        """
        Get findings formatted for event creation
        
        Returns:
            List of event-ready findings
        """
        events = []
        
        for host, findings in self.results.items():
            for finding in findings:
                port = finding["port"]
                title = finding.get("title", "Unknown")
                status = finding.get("status_code", 0)
                techs = finding.get("technologies", [])
                port_name = finding.get("port_name", f"Port {port}")
                port_desc = finding.get("port_description", "")
                subdomain = finding.get("subdomain", host)
                url = finding.get("url", f"http://{subdomain}:{port}")
                
                tech_str = ", ".join(techs[:3]) if techs else "None detected"
                
                # Create URL with subdomain:port format
                display_url = f"{subdomain}:{port}"
                
                events.append({
                    "severity": "medium",
                    "title": f"Web Service on Non-Standard Port ({port_name}) at {subdomain}",
                    "description": (
                        f"URL: {display_url}\n"
                        f"Title: {title}\n"
                        f"Status Code: {status}\n"
                        f"Technologies: {tech_str}\n"
                        f"Port: {port_desc}\n\n"
                        f"Non-standard ports may expose admin panels, development servers, "
                        f"or internal services that should not be publicly accessible."
                    ),
                    "source": "naabu",
                    "host": host,
                    "subdomain": subdomain,
                    "port": port,
                    "url": url,
                    "display_url": display_url,
                    "status_code": status,
                    "title_text": title,
                    "technologies": techs
                })
        
        return events


def scan_ports(subdomains: List[str], dns_records: Dict[str, Dict], ports: Optional[str] = None) -> Dict:
    """
    Convenience function for port scanning
    
    Args:
        subdomains: List of subdomains
        dns_records: DNS records from DNS monitor
        ports: Optional custom port list
    
    Returns:
        Port scan results
    """
    scanner = PortScanner(ports=ports)
    return scanner.scan(subdomains, dns_records)
