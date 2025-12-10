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
        
        # Subdomains with HTTP probe info
        if sections.get("subdomains", True):
            sub_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.SUBDOMAINS
            ).order_by(Snapshot.created_at.desc()).first()
            
            subdomains = sub_snapshot.data.get("subdomains", []) if sub_snapshot else []
            
            # Get HTTP data to enrich subdomains
            http_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.HTTP
            ).order_by(Snapshot.created_at.desc()).first()
            
            http_map = {}
            if http_snapshot:
                for h in http_snapshot.data.get("http_results", []):
                    url = h.get("url", "")
                    # Extract hostname from URL
                    try:
                        from urllib.parse import urlparse
                        hostname = urlparse(url).netloc
                        if hostname not in http_map:
                            http_map[hostname] = h
                    except:
                        pass
            
            # Build subdomain table data with HTTP info
            subdomain_table = []
            for sub in subdomains:
                http_info = http_map.get(sub, {})
                subdomain_table.append({
                    "subdomain": sub,
                    "status_code": http_info.get("status_code", "-"),
                    "title": http_info.get("title", "-"),
                    "technologies": http_info.get("technologies", []),
                    "content_length": http_info.get("content_length", "-")
                })
            
            data["subdomains"] = subdomain_table
            data["subdomain_count"] = len(subdomains)
        
        # DNS Records with IP info
        if sections.get("dns_records", True):
            dns_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.DNS
            ).order_by(Snapshot.created_at.desc()).first()
            
            dns_records = dns_snapshot.data.get("dns_records", {}) if dns_snapshot else {}
            data["dns_records"] = dns_records
            data["dns_count"] = len(dns_records)
            
            # Build IP table - extract unique IPs from DNS records
            ip_table = []
            seen_ips = set()
            for subdomain, records in dns_records.items():
                if isinstance(records, dict):
                    for ip in records.get("A", []):
                        if ip not in seen_ips:
                            seen_ips.add(ip)
                            ip_table.append({
                                "ip": ip,
                                "subdomain": subdomain,
                                "ports": [],
                                "vulns": []
                            })
            data["ip_table"] = ip_table
        
        # HTTP Endpoints
        if sections.get("http_endpoints", True):
            http_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.HTTP
            ).order_by(Snapshot.created_at.desc()).first()
            
            data["http_endpoints"] = http_snapshot.data.get("http_results", []) if http_snapshot else []
            data["http_count"] = len(data["http_endpoints"])
        
        # Shodan Data - ports and vulnerabilities
        if sections.get("vulnerabilities", True):
            shodan_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.SHODAN
            ).order_by(Snapshot.created_at.desc()).first()
            
            shodan_data = shodan_snapshot.data if shodan_snapshot else {}
            data["shodan_hosts"] = shodan_data.get("hosts", [])
            data["shodan_vulns"] = []
            
            # Extract vulnerabilities from Shodan
            for host in data.get("shodan_hosts", []):
                ip = host.get("ip_str", "")
                ports = host.get("ports", [])
                vulns = host.get("vulns", [])
                
                # Update IP table with Shodan data
                for ip_entry in data.get("ip_table", []):
                    if ip_entry["ip"] == ip:
                        ip_entry["ports"] = ports
                        ip_entry["vulns"] = vulns
                
                for vuln_id in vulns:
                    data["shodan_vulns"].append({
                        "id": vuln_id,
                        "ip": ip,
                        "source": "shodan"
                    })
        
        # Nuclei Vulnerabilities
        if sections.get("vulnerabilities", True):
            nuclei_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.NUCLEI
            ).order_by(Snapshot.created_at.desc()).first()
            
            data["nuclei_vulns"] = nuclei_snapshot.data.get("findings", []) if nuclei_snapshot else []
            data["vuln_count"] = len(data["nuclei_vulns"]) + len(data.get("shodan_vulns", []))
            
            # Count by severity
            data["vuln_by_severity"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for vuln in data["nuclei_vulns"]:
                sev = vuln.get("severity", "info").lower()
                if sev in data["vuln_by_severity"]:
                    data["vuln_by_severity"][sev] += 1
        
        # Takeover findings from DNS scan metadata
        dns_snapshot = self.db.query(Snapshot).filter(
            Snapshot.project_id == project.id,
            Snapshot.type == SnapshotType.DNS
        ).order_by(Snapshot.created_at.desc()).first()
        
        data["takeover_findings"] = []
        if dns_snapshot and dns_snapshot.scan_metadata:
            data["takeover_findings"] = dns_snapshot.scan_metadata.get("takeover_findings", [])
        
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
        
        # Aggregate vulnerabilities by severity
        vuln_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for p in projects_data:
            for sev, count in p.get("vuln_by_severity", {}).items():
                vuln_severity[sev] += count
        
        # Calculate security score (simplified)
        critical_weight = vuln_severity["critical"] * 40
        high_weight = vuln_severity["high"] * 20
        medium_weight = vuln_severity["medium"] * 5
        low_weight = vuln_severity["low"] * 1
        
        total_penalty = critical_weight + high_weight + medium_weight + low_weight
        security_score = max(0, min(100, 100 - total_penalty))
        
        return {
            "total_projects": len(projects_data),
            "total_subdomains": total_subdomains,
            "total_http_endpoints": total_http,
            "total_vulnerabilities": total_vulns,
            "vuln_by_severity": vuln_severity,
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
