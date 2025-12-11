"""
Report Generator Service
Generates HTML and PDF reports for projects
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session
import os

from app.models import Project, ScanLog, Snapshot, SnapshotType, Event, EventType, SeverityLevel

logger = logging.getLogger(__name__)

# Template directory
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "web", "templates", "_report")


class ReportGenerator:
    """Generate HTML and PDF reports for projects"""
    
    def __init__(self, db: Session):
        self.db = db
        self.env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=True
        )
    
    def _get_project_data(self, project: Project, sections: Dict[str, bool]) -> Dict[str, Any]:
        """Gather all data for a single project"""
        data = {
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "created_at": project.created_at,
            "last_scan_at": project.last_scan_at,
            "domains": [d.name for d in project.domains if d.is_active],
        }
        
        # Get DNS Records first (needed for IP mapping)
        dns_snapshot = self.db.query(Snapshot).filter(
            Snapshot.project_id == project.id,
            Snapshot.type == SnapshotType.DNS
        ).order_by(Snapshot.created_at.desc()).first()
        
        dns_records = dns_snapshot.data.get("dns_records", {}) if dns_snapshot else {}
        data["dns_records"] = dns_records
        data["dns_count"] = len(dns_records)
        
        # Build IP to subdomains mapping from DNS
        ip_to_subdomains = {}  # {ip: [subdomain1, subdomain2, ...]}
        for subdomain, records in dns_records.items():
            if isinstance(records, dict):
                # Handle both "a" (from scanner) and "A" (legacy) keys
                a_records = records.get("a", records.get("A", []))
                for ip in a_records:
                    if ip not in ip_to_subdomains:
                        ip_to_subdomains[ip] = []
                    ip_to_subdomains[ip].append(subdomain)
        
        # Get HTTP data - stored as http_records dict keyed by URL
        http_snapshot = self.db.query(Snapshot).filter(
            Snapshot.project_id == project.id,
            Snapshot.type == SnapshotType.HTTP
        ).order_by(Snapshot.created_at.desc()).first()
        
        # http_records is a dict: {url: {status_code, title, technologies, ...}}
        http_records = http_snapshot.data.get("http_records", {}) if http_snapshot else {}
        http_endpoints_list = list(http_records.values())  # Convert dict values to list
        data["http_endpoints"] = http_endpoints_list
        data["http_count"] = len(http_endpoints_list)
        
        # Build http_map for subdomain enrichment (extract hostname from URL)
        http_map = {}
        for url, record in http_records.items():
            try:
                from urllib.parse import urlparse
                hostname = urlparse(url).netloc
                if hostname not in http_map:
                    http_map[hostname] = record
            except:
                pass
        
        # Calculate status code distribution for charts
        status_2xx = 0
        status_3xx = 0
        status_4xx_5xx = 0
        for ep in http_endpoints_list:
            status = ep.get("status_code", 0)
            if isinstance(status, int):
                if 200 <= status < 300:
                    status_2xx += 1
                elif 300 <= status < 400:
                    status_3xx += 1
                elif status >= 400:
                    status_4xx_5xx += 1
        
        data["status_codes"] = {
            "2xx": status_2xx,
            "3xx": status_3xx,
            "4xx_5xx": status_4xx_5xx
        }
        
        # Open Ports (Non-Standard) - from SnapshotType.PORTS
        ports_snapshot = self.db.query(Snapshot).filter(
            Snapshot.project_id == project.id,
            Snapshot.type == SnapshotType.PORTS
        ).order_by(Snapshot.created_at.desc()).first()
        
        open_ports = []
        if ports_snapshot and ports_snapshot.data:
            port_findings = ports_snapshot.data.get("port_findings", {})
            for host, findings_list in port_findings.items():
                for finding in findings_list:
                    status = finding.get("status_code", 0)
                    # Filter: status 200-499 only (exclude 5xx errors)
                    if isinstance(status, int) and 200 <= status < 500:
                        open_ports.append({
                            "url": finding.get("url", ""),
                            "port": finding.get("port", 0),
                            "status_code": status,
                            "title": finding.get("title", "-"),
                            "technologies": finding.get("technologies", []),
                            "screenshot": finding.get("screenshot", "")
                        })
        
        # Sort by port number, limit for PDF
        open_ports.sort(key=lambda x: x["port"])
        data["open_ports"] = open_ports[:30]  # Show top 30 in PDF
        
        # Subdomains with HTTP probe info and DNS records
        if sections.get("subdomains", True):
            sub_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.SUBDOMAINS
            ).order_by(Snapshot.created_at.desc()).first()
            
            subdomains = sub_snapshot.data.get("subdomains", []) if sub_snapshot else []
            
            # Build subdomain table data with HTTP info and DNS records
            subdomain_table = []
            for sub in subdomains:
                http_info = http_map.get(sub, {})
                # Get DNS records for this subdomain
                sub_dns = dns_records.get(sub, {})
                subdomain_table.append({
                    "subdomain": sub,
                    "status_code": http_info.get("status_code", "-"),
                    "title": http_info.get("title", "-"),
                    "technologies": http_info.get("technologies", []),
                    "content_length": http_info.get("content_length", "-"),
                    # DNS records
                    "dns": {
                        "a": sub_dns.get("a", sub_dns.get("A", [])),
                        "aaaa": sub_dns.get("aaaa", sub_dns.get("AAAA", [])),
                        "cname": sub_dns.get("cname", sub_dns.get("CNAME", [])),
                        "mx": sub_dns.get("mx", sub_dns.get("MX", [])),
                        "txt": sub_dns.get("txt", sub_dns.get("TXT", []))
                    }
                })
            
            # Sort: entries with HTTP status first (not "-"), then alphabetically
            def sort_key(item):
                has_status = item["status_code"] != "-"
                return (0 if has_status else 1, item["subdomain"])
            
            subdomain_table.sort(key=sort_key)
            
            data["subdomains"] = subdomain_table
            data["subdomain_count"] = len(subdomains)
        
        # Shodan Data - correctly access shodan_results dictionary
        shodan_snapshot = self.db.query(Snapshot).filter(
            Snapshot.project_id == project.id,
            Snapshot.type == SnapshotType.SHODAN
        ).order_by(Snapshot.created_at.desc()).first()
        
        shodan_results = {}
        if shodan_snapshot and shodan_snapshot.data:
            shodan_results = shodan_snapshot.data.get("shodan_results", {})
        
        data["shodan_vulns"] = []
        shodan_vuln_count = 0
        
        # Build IP table with Shodan data
        # IP table format: {ip, subdomains[], ports[], org, vulns[]}
        ip_table = []
        for ip, subdomains_list in ip_to_subdomains.items():
            shodan_info = shodan_results.get(ip, {})
            ports = shodan_info.get("ports", [])
            vulns = shodan_info.get("vulns", [])
            org = shodan_info.get("org", "")
            country = shodan_info.get("country", "")
            
            ip_table.append({
                "ip": ip,
                "subdomains": subdomains_list,  # List of subdomains resolving to this IP
                "ports": ports,
                "vulns": vulns,
                "org": org,
                "country": country
            })
            
            # Count Shodan vulns
            for vuln_id in vulns:
                shodan_vuln_count += 1
                data["shodan_vulns"].append({
                    "id": vuln_id,
                    "ip": ip,
                    "source": "shodan"
                })
        
        data["ip_table"] = ip_table
        
        # Nuclei Vulnerabilities
        nuclei_snapshot = self.db.query(Snapshot).filter(
            Snapshot.project_id == project.id,
            Snapshot.type == SnapshotType.NUCLEI
        ).order_by(Snapshot.created_at.desc()).first()
        
        nuclei_vulns = nuclei_snapshot.data.get("findings", []) if nuclei_snapshot else []
        data["nuclei_vulns"] = nuclei_vulns
        
        # Takeover findings from DNS scan metadata
        data["takeover_findings"] = []
        if dns_snapshot and dns_snapshot.scan_metadata:
            data["takeover_findings"] = dns_snapshot.scan_metadata.get("takeover_findings", [])
        
        # Total vulnerability count = Nuclei + Shodan + Takeovers
        data["vuln_count"] = len(nuclei_vulns) + shodan_vuln_count + len(data["takeover_findings"])
        
        # Get Events data for severity chart (from Events tab)
        events = self.db.query(Event).filter(
            Event.project_id == project.id
        ).all()
        
        data["events_by_severity"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for event in events:
            sev = event.severity.value.lower() if event.severity else "info"
            if sev in data["events_by_severity"]:
                data["events_by_severity"][sev] += 1
        data["total_events"] = len(events)
        
        # Scan History
        if sections.get("scan_history", True):
            scans = self.db.query(ScanLog).filter(
                ScanLog.project_id == project.id
            ).order_by(ScanLog.started_at.desc()).limit(10).all()
            
            data["scan_history"] = [
                {
                    "id": s.id,
                    "mode": s.scan_mode,
                    "status": s.status,
                    "started_at": s.started_at,
                    "completed_at": s.completed_at,
                    "events_generated": s.events_generated or 0
                }
                for s in scans
            ]
        
        return data
    
    def _calculate_summary(self, projects_data: List[Dict]) -> Dict[str, Any]:
        """Calculate executive summary stats"""
        total_subdomains = sum(p.get("subdomain_count", 0) for p in projects_data)
        total_http = sum(p.get("http_count", 0) for p in projects_data)
        total_vulns = sum(p.get("vuln_count", 0) for p in projects_data)
        total_events = sum(p.get("total_events", 0) for p in projects_data)
        
        # Aggregate events by severity (from Events tab data)
        events_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for p in projects_data:
            for sev, count in p.get("events_by_severity", {}).items():
                events_by_severity[sev] += count
        
        # Calculate security score based on events severity
        critical_weight = events_by_severity["critical"] * 40
        high_weight = events_by_severity["high"] * 20
        medium_weight = events_by_severity["medium"] * 5
        low_weight = events_by_severity["low"] * 1
        
        total_penalty = critical_weight + high_weight + medium_weight + low_weight
        security_score = max(0, min(100, 100 - total_penalty))
        
        # Aggregate status codes for charts
        status_codes = {"2xx": 0, "3xx": 0, "4xx_5xx": 0}
        for p in projects_data:
            sc = p.get("status_codes", {})
            status_codes["2xx"] += sc.get("2xx", 0)
            status_codes["3xx"] += sc.get("3xx", 0)
            status_codes["4xx_5xx"] += sc.get("4xx_5xx", 0)
        
        return {
            "total_projects": len(projects_data),
            "total_subdomains": total_subdomains,
            "total_http_endpoints": total_http,
            "total_vulnerabilities": total_vulns,
            "total_events": total_events,
            "events_by_severity": events_by_severity,
            "status_codes": status_codes,
            "security_score": security_score,
            "generated_at": datetime.utcnow()
        }
    
    def generate_html_report(self, projects: List[Project], sections: Dict[str, bool], company: Optional[Dict] = None) -> str:
        """Generate HTML report"""
        # Gather data for all projects
        projects_data = [self._get_project_data(p, sections) for p in projects]
        
        # Calculate summary if enabled
        summary = None
        if sections.get("executive_summary", True):
            summary = self._calculate_summary(projects_data)
        
        # Default company info
        if company is None:
            company = {"name": "", "website": "", "email": ""}
        
        # Render template
        template = self.env.get_template("template.html")
        html = template.render(
            projects=projects_data,
            summary=summary,
            sections=sections,
            company=company,
            generated_at=datetime.utcnow()
        )
        
        return html
    
    def generate_pdf_report(self, projects: List[Project], sections: Dict[str, bool], company: Optional[Dict] = None) -> bytes:
        """Generate PDF report from HTML"""
        # First generate HTML
        html_content = self.generate_html_report(projects, sections, company)
        
        # Convert to PDF using weasyprint
        try:
            from weasyprint import HTML, CSS
            
            # Create PDF with custom CSS for page settings
            pdf = HTML(string=html_content).write_pdf()
            return pdf
        except ImportError:
            logger.error("weasyprint not installed. Install with: pip install weasyprint")
            raise ImportError("PDF generation requires weasyprint. Install with: pip install weasyprint")
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            raise
