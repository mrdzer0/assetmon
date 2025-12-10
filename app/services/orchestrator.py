"""
Scan orchestrator - coordinates all scanning services
"""

import logging
from typing import List, Dict, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from app.models import (
    Project, Snapshot, Event, ScanLog,
    SnapshotType, EventType, SeverityLevel
)
from app.services.scanner.subdomains import discover_subdomains
from app.services.scanner.dns_monitor import monitor_dns
from app.services.scanner.http_monitor import monitor_http
from app.services.scanner.shodan_monitor import scan_with_shodan
from app.services.scanner.endpoints import discover_endpoints
from app.services.scanner.nuclei import NucleiScanner
from app.services.scanner.port_scanner import PortScanner
from app.services.diff import subdomains as diff_subs
from app.services.diff import dns as diff_dns
from app.services.diff import http as diff_http
from app.services.diff import shodan as diff_shodan
from app.services.diff import endpoints as diff_endpoints
from app.routers.settings import get_scanner_config
from app.services.notifiers.base import NotificationManager

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Orchestrates the entire scanning process:
    1. Run all enabled scanners
    2. Compare with previous snapshots
    3. Generate events
    4. Send notifications
    5. Save new snapshots
    """

    def __init__(self, db: Session, notification_manager: NotificationManager = None):
        self.db = db
        self.notification_manager = notification_manager
        self.scan_log = None
        self.errors = []

    def run_scan(self, project_id: int, mode: str = "normal", modules: list = None) -> Dict:
        """
        Execute a complete scan for a project

        Args:
            project_id: Project ID to scan
            mode: Scan mode ("normal", "weekly", or "custom")
            modules: List of modules to run when mode is "custom"
                     Options: "normal", "endpoints", "shodan", "nuclei", "ports"

        Returns:
            Dict with scan results and statistics
        """
        logger.info(f"Starting {mode} scan for project {project_id}" + 
                    (f" with modules {modules}" if modules else ""))

        # Load project
        project = self.db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project {project_id} not found")

        if not project.is_active:
            raise ValueError(f"Project {project_id} is not active")

        # Get project domains
        domains = [d.name for d in project.domains if d.is_active]
        if not domains:
            raise ValueError(f"No active domains in project {project_id}")

        # Find existing queued scan log (created by API) or create new one
        self.scan_log = self.db.query(ScanLog).filter(
            ScanLog.project_id == project_id,
            ScanLog.status == "queued"
        ).order_by(ScanLog.started_at.desc()).first()

        if self.scan_log:
            # Update existing queued log
            self.scan_log.status = "running"
            self.scan_log.scan_mode = mode
            self.scan_log.tools_executed = {}
        else:
            # Create new scan log if none exists
            self.scan_log = ScanLog(
                project_id=project_id,
                scan_mode=mode,
                status="running",
                tools_executed={}
            )
            self.db.add(self.scan_log)
        
        self.db.commit()

        all_events = []
        snapshots_created = {}

        try:
            # Get project configuration
            config = project.config or {}
            enabled_tools = config.get("enabled_tools", {})

            # Determine which modules to run based on mode and modules list
            run_base = True  # Always run base (subdomain, dns, http) unless explicitly disabled
            run_endpoints = False
            run_shodan = False
            run_nuclei = False
            run_ports = False

            if mode == "weekly":
                # Weekly runs everything
                run_endpoints = True
                run_shodan = True
                run_nuclei = True
                run_ports = True
            elif mode == "custom" and modules:
                # Custom mode - run selected modules
                run_base = "normal" in modules
                run_endpoints = "endpoints" in modules
                run_shodan = "shodan" in modules
                run_nuclei = "nuclei" in modules
                run_ports = "ports" in modules

            # 1. Subdomain Discovery
            if run_base and enabled_tools.get("subdomains", {}).get("enabled", True):
                events, snapshot = self._run_subdomain_scan(project, domains, enabled_tools)
                all_events.extend(events)
                if snapshot:
                    snapshots_created["subdomains"] = snapshot

            # 2. DNS Monitoring
            if run_base and enabled_tools.get("dns", {}).get("enabled", True):
                # Get subdomains from snapshot or previous scan
                subdomains = self._get_current_subdomains(project_id, snapshots_created)
                if subdomains:
                    events, snapshot = self._run_dns_scan(project, subdomains)
                    all_events.extend(events)
                    if snapshot:
                        snapshots_created["dns"] = snapshot

            # 3. HTTP Monitoring
            if run_base and enabled_tools.get("http", {}).get("enabled", True):
                subdomains = self._get_current_subdomains(project_id, snapshots_created)
                if subdomains:
                    events, snapshot = self._run_http_scan(project, subdomains, enabled_tools)
                    all_events.extend(events)
                    if snapshot:
                        snapshots_created["http"] = snapshot

            # 4. Port Scanning (for non-standard web ports)
            # Get port config from database (ScannerConfig table) where UI saves it
            # This picks up screenshot_enabled and other settings saved via /settings/scanners
            db_port_config = get_scanner_config(self.db, "port_config")
            port_config = {**enabled_tools.get("ports", {}), **db_port_config}
            if run_ports and port_config.get("enabled", True):
                subdomains = self._get_current_subdomains(project_id, snapshots_created)
                # Get DNS snapshot from current scan or fetch from previous scan
                dns_snapshot = snapshots_created.get("dns")
                if not dns_snapshot:
                    # Fetch most recent DNS snapshot from database
                    dns_snapshot = self.db.query(Snapshot).filter(
                        Snapshot.project_id == project_id,
                        Snapshot.type == SnapshotType.DNS
                    ).order_by(Snapshot.created_at.desc()).first()
                
                if subdomains and dns_snapshot:
                    events, snapshot = self._run_port_scan(project, subdomains, dns_snapshot, port_config)
                    all_events.extend(events)
                    if snapshot:
                        snapshots_created["ports"] = snapshot
                elif not subdomains:
                    logger.warning(f"Port scan skipped: no subdomains found for project {project_id}")
                elif not dns_snapshot:
                    logger.warning(f"Port scan skipped: no DNS snapshot found for project {project_id}")

            # 5. Shodan Monitoring
            # In custom mode, run if user selected it. In weekly mode, check config.
            shodan_enabled = enabled_tools.get("shodan", {}).get("enabled", False) if mode != "custom" else True
            if run_shodan and shodan_enabled:
                ips = self._get_current_ips(project_id, snapshots_created)
                if ips:
                    # Get IP to subdomain mapping from DNS records
                    ip_to_subdomains = self._get_ip_to_subdomain_mapping(project_id, snapshots_created)
                    events, snapshot = self._run_shodan_scan(project, ips, ip_to_subdomains)
                    all_events.extend(events)
                    if snapshot:
                        snapshots_created["shodan"] = snapshot
                else:
                    logger.warning(f"Shodan scan skipped: no IPs found for project {project_id}")

            # 6. Endpoint Discovery
            endpoints_enabled = enabled_tools.get("endpoints", {}).get("enabled", False) if mode != "custom" else True
            if run_endpoints and endpoints_enabled:
                subdomains = self._get_current_subdomains(project_id, snapshots_created)
                if subdomains:
                    events, snapshot = self._run_endpoint_scan(project, domains, subdomains, enabled_tools)
                    all_events.extend(events)
                    if snapshot:
                        snapshots_created["endpoints"] = snapshot
                else:
                    logger.warning(f"Endpoints scan skipped: no subdomains found for project {project_id}")

            # 7. Nuclei Vulnerability Scan
            nuclei_config = enabled_tools.get("nuclei", {})
            nuclei_enabled = nuclei_config.get("enabled", False) if mode != "custom" else True
            if run_nuclei and nuclei_enabled:
                events, snapshot = self._run_nuclei_scan(project, snapshots_created, nuclei_config)
                all_events.extend(events)
                if snapshot:
                    snapshots_created["nuclei"] = snapshot

            # Save all events
            for event_data in all_events:
                event = Event(
                    project_id=project_id,
                    type=event_data["type"],
                    severity=event_data["severity"],
                    summary=event_data["summary"],
                    details=event_data.get("details"),
                    related_entities=event_data.get("related_entities")
                )
                self.db.add(event)

            self.db.commit()

            # Send notifications
            if self.notification_manager and all_events:
                self.notification_manager.send_notifications(
                    all_events,
                    project_name=project.name,
                    scan_mode=mode
                )

            # Update scan log
            self.scan_log.status = "completed"
            self.scan_log.completed_at = datetime.utcnow()
            self.scan_log.events_generated = len(all_events)
            if self.errors:
                self.scan_log.errors = self.errors

            # Update project last scan time
            if mode == "weekly":
                project.last_weekly_scan_at = datetime.utcnow()
            project.last_scan_at = datetime.utcnow()

            self.db.commit()

            logger.info(f"Scan completed: {len(all_events)} events generated")

            return {
                "success": True,
                "scan_id": self.scan_log.id,
                "project_id": project_id,
                "mode": mode,
                "events_generated": len(all_events),
                "snapshots_created": list(snapshots_created.keys()),
                "errors": self.errors
            }

        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)

            if self.scan_log:
                self.scan_log.status = "failed"
                self.scan_log.completed_at = datetime.utcnow()
                self.scan_log.errors = self.errors + [str(e)]
                self.db.commit()

            raise

    def _run_subdomain_scan(self, project: Project, domains: List[str], config: Dict) -> tuple:
        """Run subdomain discovery and diff"""
        logger.info("Running subdomain discovery...")
        start_time = datetime.utcnow()

        try:
            # Get enabled sources
            subdomain_config = config.get("subdomains", {})
            sources = subdomain_config.get("sources", ["subfinder", "assetfinder", "crtsh", "chaos"])

            # Run discovery
            result = discover_subdomains(domains, sources=sources)

            # Log tool execution
            duration = (datetime.utcnow() - start_time).total_seconds()
            self.scan_log.tools_executed["subdomains"] = {
                "duration": duration,
                "count": result["count"]
            }
            self.db.commit()

            # Get previous snapshot
            prev_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.SUBDOMAINS
            ).order_by(Snapshot.created_at.desc()).first()

            # Diff and generate events
            events = []
            if prev_snapshot:
                old_subdomains = prev_snapshot.data.get("subdomains", [])
                new_subdomains = result["subdomains"]
                events = diff_subs.diff_subdomains(old_subdomains, new_subdomains)

            # Create new snapshot
            snapshot = Snapshot(
                project_id=project.id,
                type=SnapshotType.SUBDOMAINS,
                data={"subdomains": result["subdomains"]},
                scan_metadata={"sources": result.get("sources", {})}
            )
            self.db.add(snapshot)
            self.db.commit()

            return events, snapshot

        except Exception as e:
            logger.error(f"Subdomain scan failed: {e}")
            self.errors.append(f"Subdomain scan: {str(e)}")
            return [], None

    def _run_dns_scan(self, project: Project, subdomains: List[str]) -> tuple:
        """Run DNS monitoring and diff"""
        logger.info(f"Running DNS monitoring for {len(subdomains)} subdomains...")
        start_time = datetime.utcnow()

        try:
            result = monitor_dns(subdomains)

            duration = (datetime.utcnow() - start_time).total_seconds()
            self.scan_log.tools_executed["dns"] = {
                "duration": duration,
                "resolved": result["stats"]["resolved"]
            }
            self.db.commit()

            # Get previous snapshot
            prev_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.DNS
            ).order_by(Snapshot.created_at.desc()).first()

            # Diff and generate events
            events = []
            if prev_snapshot:
                old_dns = prev_snapshot.data.get("dns_records", {})
                new_dns = result["dns_records"]
                events = diff_dns.diff_dns(old_dns, new_dns)

            # Add takeover findings as high-severity events
            for finding in result.get("takeover_findings", []):
                events.append({
                    "type": EventType.TAKEOVER_SUSPECTED,
                    "severity": SeverityLevel.HIGH if finding["severity"] == "high" else SeverityLevel.CRITICAL,
                    "summary": f"Subdomain takeover suspected: {finding['subdomain']} -> {finding['cname']} ({finding['service']})",
                    "details": finding,
                    "related_entities": {
                        "subdomain": finding["subdomain"],
                        "cname": finding["cname"],
                        "service": finding["service"]
                    }
                })

            # Create snapshot
            snapshot = Snapshot(
                project_id=project.id,
                type=SnapshotType.DNS,
                data={"dns_records": result["dns_records"]},
                scan_metadata={"stats": result["stats"], "takeover_findings": result.get("takeover_findings", [])}
            )
            self.db.add(snapshot)
            self.db.commit()

            return events, snapshot

        except Exception as e:
            logger.error(f"DNS scan failed: {e}")
            self.errors.append(f"DNS scan: {str(e)}")
            return [], None

    def _run_http_scan(self, project: Project, subdomains: List[str], config: Dict) -> tuple:
        """Run HTTP monitoring and diff"""
        logger.info(f"Running HTTP monitoring for {len(subdomains)} subdomains...")
        start_time = datetime.utcnow()

        try:
            http_config = config.get("http", {})
            threads = http_config.get("threads", 50)
            timeout = http_config.get("timeout", 10)

            result = monitor_http(subdomains, threads=threads, timeout=timeout)

            duration = (datetime.utcnow() - start_time).total_seconds()
            self.scan_log.tools_executed["http"] = {
                "duration": duration,
                "success": result["stats"]["success"]
            }
            self.db.commit()

            # Get previous snapshot
            prev_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.HTTP
            ).order_by(Snapshot.created_at.desc()).first()

            # Diff
            events = []
            if prev_snapshot:
                old_http = prev_snapshot.data.get("http_records", {})
                new_http = result["http_records"]
                events = diff_http.diff_http(old_http, new_http)

            # Add takeover findings
            for finding in result.get("takeover_findings", []):
                events.append({
                    "type": EventType.TAKEOVER_SUSPECTED,
                    "severity": SeverityLevel.HIGH,
                    "summary": f"Takeover fingerprint detected: {finding['url']}",
                    "details": finding,
                    "related_entities": {"url": finding["url"]}
                })

            # Create snapshot
            snapshot = Snapshot(
                project_id=project.id,
                type=SnapshotType.HTTP,
                data={"http_records": result["http_records"]},
                scan_metadata={"stats": result["stats"]}
            )
            self.db.add(snapshot)
            self.db.commit()

            return events, snapshot

        except Exception as e:
            logger.error(f"HTTP scan failed: {e}")
            self.errors.append(f"HTTP scan: {str(e)}")
            return [], None

    def _run_shodan_scan(self, project: Project, ips: List[str], ip_to_subdomains: Dict[str, List[str]] = None) -> tuple:
        """Run Shodan scanning and diff"""
        logger.info(f"Running Shodan scan for {len(ips)} IPs...")
        start_time = datetime.utcnow()

        try:
            result = scan_with_shodan(ips, query_mode="ip")

            duration = (datetime.utcnow() - start_time).total_seconds()
            self.scan_log.tools_executed["shodan"] = {
                "duration": duration,
                "found": result["stats"]["found"]
            }
            self.db.commit()

            # Get previous snapshot
            prev_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.SHODAN
            ).order_by(Snapshot.created_at.desc()).first()

            # Diff
            events = []
            if ip_to_subdomains is None:
                ip_to_subdomains = {}

            if prev_snapshot:
                old_shodan = prev_snapshot.data.get("shodan_results", {})
                new_shodan = result["shodan_results"]
                events = diff_shodan.diff_shodan(old_shodan, new_shodan, ip_to_subdomains)
            else:
                # First scan - create events for initial findings
                new_shodan = result["shodan_results"]
                if ip_to_subdomains is None:
                    ip_to_subdomains = {}

                for ip, data in new_shodan.items():
                    # Get related subdomains for this IP
                    related_subdomains = ip_to_subdomains.get(ip, [])

                    # Create events for open ports
                    for port in data.get("ports", []):
                        events.append({
                            "type": EventType.PORT_NEW,
                            "severity": SeverityLevel.MEDIUM,
                            "summary": f"Open port discovered on {ip}: {port}",
                            "details": {
                                "ip": ip,
                                "port": port,
                                "hostnames": data.get("hostnames", []),
                                "subdomains": related_subdomains
                            },
                            "related_entities": {
                                "ip": ip,
                                "port": port
                            }
                        })

                    # Create events for vulnerabilities
                    for vuln in data.get("vulns", []):
                        events.append({
                            "type": EventType.VULNERABILITY_FOUND,
                            "severity": SeverityLevel.HIGH,
                            "summary": f"Vulnerability discovered on {ip}: {vuln}",
                            "details": {
                                "ip": ip,
                                "cve": vuln,
                                "hostnames": data.get("hostnames", []),
                                "subdomains": related_subdomains
                            },
                            "related_entities": {
                                "ip": ip,
                                "cve": vuln
                            }
                        })

            # Create snapshot
            snapshot = Snapshot(
                project_id=project.id,
                type=SnapshotType.SHODAN,
                data={"shodan_results": result["shodan_results"]},
                scan_metadata={"stats": result["stats"], "vulnerabilities": result.get("vulnerabilities", [])}
            )
            self.db.add(snapshot)
            self.db.commit()

            return events, snapshot

        except Exception as e:
            logger.error(f"Shodan scan failed: {e}")
            self.errors.append(f"Shodan scan: {str(e)}")
            return [], None

    def _run_endpoint_scan(self, project: Project, domains: List[str], subdomains: List[str], config: Dict) -> tuple:
        """Run endpoint discovery and diff"""
        logger.info(f"Running endpoint discovery (weekly scan)...")
        start_time = datetime.utcnow()

        try:
            endpoint_config = config.get("endpoints", {})
            sources = endpoint_config.get("sources", ["waybackurls", "gau"])

            result = discover_endpoints(domains, subdomains=subdomains, sources=sources)

            duration = (datetime.utcnow() - start_time).total_seconds()
            self.scan_log.tools_executed["endpoints"] = {
                "duration": duration,
                "total_urls": result["stats"]["total_urls"]
            }
            self.db.commit()

            # Get existing HTTP data
            http_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.HTTP
            ).order_by(Snapshot.created_at.desc()).first()

            http_data = {}
            if http_snapshot and http_snapshot.data:
                http_data = http_snapshot.data.get("http_records", {})

            # Probe new endpoints with httpx (sample to avoid overload)
            logger.info(f"Probing endpoints with httpx...")
            new_urls = [url for url in result["urls"] if url not in http_data]

            if new_urls:
                # Limit to 2000 URLs (increased from 500) to avoid long scan times but capture more data
                limit = 2000
                sample_urls = new_urls[:limit] if len(new_urls) > limit else new_urls
                logger.info(f"Probing {len(sample_urls)} new endpoints (out of {len(new_urls)} total new)")

                try:
                    http_config = config.get("http", {})
                    threads = http_config.get("threads", 50)
                    timeout = http_config.get("timeout", 10)

                    probe_results = monitor_http(sample_urls, threads=threads, timeout=timeout)

                    # Merge new results with existing http_data
                    if probe_results and "http_records" in probe_results:
                        http_data.update(probe_results["http_records"])
                        logger.info(f"Probed {len(probe_results['http_records'])} endpoints successfully")

                        # Update HTTP snapshot with new endpoint data
                        if http_snapshot:
                            http_snapshot.data["http_records"].update(probe_results["http_records"])
                            self.db.commit()

                except Exception as e:
                    logger.error(f"Failed to probe endpoints: {e}")
                    # Continue with existing data only

            # Categorize and enrich endpoints
            from app.utils.endpoint_categorizer import categorize_endpoints
            endpoint_categorizations = categorize_endpoints(result["urls"])

            # Enrich URLs with HTTP data and categorization
            enriched_urls = []
            sensitive_accessible_events = []

            # Helper function to extract base URL for HTTP data matching
            from urllib.parse import urlparse
            def get_base_url(url):
                parsed = urlparse(url)
                return f"{parsed.scheme}://{parsed.netloc}"

            for url in result["urls"]:
                categorization = endpoint_categorizations.get(url, {})

                # Try exact match first, then base URL match
                http_info = http_data.get(url, {})
                if not http_info:
                    base_url = get_base_url(url)
                    http_info = http_data.get(base_url, {})

                enriched_url = {
                    "url": url,
                    "status_code": http_info.get("status_code"),
                    "title": http_info.get("title"),
                    "categories": categorization.get("categories", []),
                    "is_sensitive": categorization.get("is_sensitive", False),
                    "highest_severity": categorization.get("highest_severity", "low")
                }
                enriched_urls.append(enriched_url)

                # Generate events for sensitive + accessible endpoints
                if categorization.get("is_sensitive") and http_info.get("status_code") == 200:
                    categories_str = ', '.join([c['name'] for c in categorization['categories']])
                    severity_map = {
                        'high': SeverityLevel.HIGH,
                        'medium': SeverityLevel.MEDIUM,
                        'low': SeverityLevel.LOW
                    }

                    sensitive_accessible_events.append({
                        "type": EventType.ENDPOINT_NEW,
                        "severity": severity_map.get(categorization['highest_severity'], SeverityLevel.MEDIUM),
                        "summary": f"Sensitive endpoint accessible: {url.split('/')[-1] or url.split('/')[-2]} [{categories_str}]",
                        "details": {
                            "url": url,
                            "status_code": http_info.get("status_code"),
                            "title": http_info.get("title"),
                            "categories": categorization['categories'],
                            "matched_keywords": categorization.get("matched_keywords", []),
                            "matched_extensions": categorization.get("matched_extensions", []),
                            "severity": categorization['highest_severity'],
                            "change_type": "sensitive_accessible"
                        },
                        "related_entities": {
                            "url": url,
                            "categories": categories_str
                        }
                    })

            if sensitive_accessible_events:
                logger.warning(f"Found {len(sensitive_accessible_events)} sensitive accessible endpoints!")

            # Analyze JS files (sample 50 for performance)
            js_file_analysis = {}
            secret_events = []
            if result.get("js_files"):
                logger.info(f"Analyzing {len(result['js_files'])} JS files...")
                from app.services.scanner.jsfile_analyzer import analyze_js_files

                # Analyze sample or all files (max 100)
                sample_size = min(100, len(result["js_files"]))
                js_file_analysis = analyze_js_files(
                    result["js_files"],
                    check_content=True,
                    sample_size=sample_size if len(result["js_files"]) > 100 else None
                )
                logger.info(f"JS file analysis complete: {len(js_file_analysis)} files analyzed")

                # Generate events for files with secrets
                for url, analysis in js_file_analysis.items():
                    secrets_info = analysis.get('secrets', {})
                    if secrets_info.get('has_secrets'):
                        risk_level = secrets_info.get('risk_level', 'low')

                        # Determine severity based on risk level
                        severity = SeverityLevel.HIGH if risk_level == 'high' else (
                            SeverityLevel.MEDIUM if risk_level == 'medium' else SeverityLevel.LOW
                        )

                        # Build secret summary
                        secret_types = [s['type'] for s in secrets_info.get('secrets_found', [])]
                        secret_summary = ', '.join(secret_types[:3])
                        if len(secret_types) > 3:
                            secret_summary += f' +{len(secret_types) - 3} more'

                        secret_events.append({
                            "type": EventType.JS_FILE_NEW,  # Using existing enum
                            "severity": severity,
                            "summary": f"Secrets detected in JS file: {url.split('/')[-1]} ({risk_level} risk)",
                            "details": {
                                "url": url,
                                "risk_level": risk_level,
                                "secrets_found": secrets_info.get('secrets_found', []),
                                "suspicious_keywords": secrets_info.get('suspicious_keywords', []),
                                "secret_types": secret_types
                            },
                            "related_entities": {
                                "url": url,
                                "risk_level": risk_level
                            }
                        })

                if secret_events:
                    logger.warning(f"Found {len(secret_events)} JS files with secrets!")

            # Get previous snapshot
            prev_snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project.id,
                Snapshot.type == SnapshotType.ENDPOINTS
            ).order_by(Snapshot.created_at.desc()).first()

            # Diff
            events = []
            if prev_snapshot:
                old_endpoints = prev_snapshot.data
                old_analysis = prev_snapshot.data.get("js_file_analysis", {})
                new_endpoints = {
                    "urls": result["urls"],
                    "js_files": result["js_files"],
                    "js_file_analysis": js_file_analysis
                }
                events = diff_endpoints.diff_endpoints(old_endpoints, new_endpoints, old_analysis)

            # Merge all events (diff + secrets + sensitive accessible)
            all_events = events + secret_events + sensitive_accessible_events

            # Count sensitive endpoints
            sensitive_count = sum(1 for u in enriched_urls if u.get('is_sensitive'))
            accessible_sensitive_count = len(sensitive_accessible_events)

            # Create snapshot
            snapshot = Snapshot(
                project_id=project.id,
                type=SnapshotType.ENDPOINTS,
                data={
                    "urls": result["urls"],
                    "enriched_urls": enriched_urls,  # Store enriched data
                    "js_files": result["js_files"],
                    "api_endpoints": result["api_endpoints"],
                    "js_file_analysis": js_file_analysis  # Store analysis results
                },
                scan_metadata={
                    "stats": result["stats"],
                    "sources": result.get("sources", {}),
                    "js_files_analyzed": len(js_file_analysis),
                    "js_files_total": len(result.get("js_files", [])),
                    "sensitive_endpoints": sensitive_count,
                    "accessible_sensitive_endpoints": accessible_sensitive_count
                }
            )
            self.db.add(snapshot)
            self.db.commit()

            return all_events, snapshot

        except Exception as e:
            logger.error(f"Endpoint scan failed: {e}")
            self.errors.append(f"Endpoint scan: {str(e)}")
            return [], None

    def _get_current_subdomains(self, project_id: int, snapshots: Dict) -> List[str]:
        """Get subdomains from current scan or previous snapshot"""
        # Check if we just scanned subdomains
        if "subdomains" in snapshots:
            return snapshots["subdomains"].data.get("subdomains", [])

        # Get from latest snapshot
        snapshot = self.db.query(Snapshot).filter(
            Snapshot.project_id == project_id,
            Snapshot.type == SnapshotType.SUBDOMAINS
        ).order_by(Snapshot.created_at.desc()).first()

        if snapshot:
            return snapshot.data.get("subdomains", [])

        return []

    def _get_current_ips(self, project_id: int, snapshots: Dict) -> List[str]:
        """Get IPs from DNS scan"""
        # Check if we just scanned DNS
        if "dns" in snapshots:
            dns_records = snapshots["dns"].data.get("dns_records", {})
        else:
            # Get from latest snapshot
            snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project_id,
                Snapshot.type == SnapshotType.DNS
            ).order_by(Snapshot.created_at.desc()).first()

            if not snapshot:
                return []

            dns_records = snapshot.data.get("dns_records", {})

        # Extract IPs
        ips = set()
        for record in dns_records.values():
            ips.update(record.get("a", []))

        return list(ips)

    def _get_ip_to_subdomain_mapping(self, project_id: int, snapshots: Dict) -> Dict[str, List[str]]:
        """Get mapping of IP addresses to subdomains"""
        # Check if we just scanned DNS
        if "dns" in snapshots:
            dns_records = snapshots["dns"].data.get("dns_records", {})
        else:
            # Get from latest snapshot
            snapshot = self.db.query(Snapshot).filter(
                Snapshot.project_id == project_id,
                Snapshot.type == SnapshotType.DNS
            ).order_by(Snapshot.created_at.desc()).first()

            if not snapshot:
                return {}

            dns_records = snapshot.data.get("dns_records", {})

        # Build mapping: IP -> [subdomains]
        ip_to_subdomains = {}
        for subdomain, record in dns_records.items():
            for ip in record.get("a", []):
                if ip not in ip_to_subdomains:
                    ip_to_subdomains[ip] = []
                ip_to_subdomains[ip].append(subdomain)

        return ip_to_subdomains

    def _run_port_scan(self, project: Project, subdomains: List[str], dns_snapshot: Snapshot, config: Dict):
        """Run port scanning for non-standard web ports"""
        logger.info(f"Running port scan for project {project.id}")
        events = []
        
        try:
            # Get DNS records from snapshot
            dns_records = dns_snapshot.data.get("dns_records", {})
            
            # Get custom ports if configured
            custom_ports = config.get("ports")
            
            # Check if screenshots are enabled
            screenshot_enabled = config.get("screenshot_enabled", False)
            screenshot_dir = None
            
            if screenshot_enabled:
                # Create project-specific screenshot directory in web/static where FastAPI serves from
                import os
                base_screenshot_dir = os.path.join("web", "static", "screenshots", "ports", str(project.id))
                os.makedirs(base_screenshot_dir, exist_ok=True)
                screenshot_dir = base_screenshot_dir
                logger.info(f"Port scan screenshots enabled, dir: {screenshot_dir}")
            
            # Run port scanner
            scanner = PortScanner(
                ports=custom_ports,
                screenshot_enabled=screenshot_enabled,
                screenshot_dir=screenshot_dir
            )
            result = scanner.scan(subdomains, dns_records)
            
            # Generate events for discovered services
            port_events = scanner.get_findings_for_events()
            
            for pe in port_events:
                events.append({
                    "type": EventType.PORT_NEW,
                    "severity": SeverityLevel.MEDIUM,
                    "summary": pe["title"],
                    "details": {
                        "description": pe["description"],
                        "source": pe.get("source", "naabu"),
                        "status_code": pe.get("status_code"),
                        "technologies": pe.get("technologies", [])
                    },
                    "related_entities": {
                        "host": pe.get("host"),
                        "port": pe.get("port"),
                        "url": pe.get("url"),
                        "source": "naabu"
                    }
                })
            
            # Create snapshot
            snapshot = Snapshot(
                project_id=project.id,
                type=SnapshotType.PORTS,
                data={
                    "scan_type": "port_scan",
                    "port_findings": result.get("port_findings", {}),
                    "stats": result.get("stats", {}),
                    "ports_scanned": result.get("ports_scanned", "")
                },
                scan_metadata={
                    "ports": result.get("ports_scanned"),
                    "targets": result.get("stats", {}).get("total_targets", 0),
                    "open_ports": result.get("stats", {}).get("open_ports_found", 0),
                    "http_services": result.get("stats", {}).get("http_services_found", 0)
                }
            )
            self.db.add(snapshot)
            self.db.commit()
            
            logger.info(f"Port scan completed: {len(port_events)} services found")
            return events, snapshot
            
        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            self.errors.append(f"Port scan failed: {str(e)}")
            return events, None

    def _run_nuclei_scan(self, project: Project, snapshots: Dict, nuclei_config: Dict):
        """Run Nuclei vulnerability scanning"""
        logger.info(f"Running Nuclei scan for project {project.id}")
        events = []

        try:
            # Get targets from HTTP snapshot (only alive hosts)
            targets = []
            http_snapshot = snapshots.get("http")
            
            if http_snapshot:
                http_records = http_snapshot.data.get("http_records", {})
            else:
                # Get from latest HTTP snapshot
                snapshot = self.db.query(Snapshot).filter(
                    Snapshot.project_id == project.id,
                    Snapshot.type == SnapshotType.HTTP
                ).order_by(Snapshot.created_at.desc()).first()
                
                http_records = snapshot.data.get("http_records", {}) if snapshot else {}
            
            # Filter to only alive hosts if configured
            scan_alive_only = nuclei_config.get("scan_alive_only", True)
            
            for url, data in http_records.items():
                status_code = data.get("status_code", 0)
                if scan_alive_only:
                    # Only include 2xx and 3xx status codes
                    if 200 <= status_code < 400:
                        targets.append(url)
                else:
                    targets.append(url)
            
            if not targets:
                logger.warning(f"No targets for Nuclei scan in project {project.id}")
                return [], None
            
            # Run Nuclei scan
            scanner = NucleiScanner(project.id, nuclei_config)
            results = scanner.scan(targets)
            
            if results.get("error"):
                self.errors.append(f"Nuclei scan error: {results['error']}")
                return [], None
            
            findings = results.get("findings", [])
            stats = results.get("stats", {})
            
            # Create events for findings
            for finding in findings:
                severity = finding.get("severity", "info").lower()
                severity_map = {
                    "critical": SeverityLevel.CRITICAL,
                    "high": SeverityLevel.HIGH,
                    "medium": SeverityLevel.MEDIUM,
                    "low": SeverityLevel.LOW,
                    "info": SeverityLevel.INFO
                }
                
                event = {
                    "type": EventType.VULNERABILITY_FOUND,
                    "severity": severity_map.get(severity, SeverityLevel.INFO),
                    "summary": f"Nuclei: {finding.get('template_name', 'Unknown')} on {finding.get('host', 'unknown')}",
                    "details": {
                        "template_id": finding.get("template_id"),
                        "template_name": finding.get("template_name"),
                        "matched_at": finding.get("matched_at"),
                        "severity": severity,
                        "description": finding.get("description"),
                        "source": "nuclei"
                    },
                    "related_entities": {
                        "host": finding.get("host"),
                        "template_id": finding.get("template_id")
                    }
                }
                events.append(event)
            
            # Save snapshot
            snapshot = Snapshot(
                project_id=project.id,
                type=SnapshotType.NUCLEI,
                data={
                    "nuclei_findings": findings,
                    "stats": stats,
                    "scanned_at": results.get("scanned_at"),
                    "targets_count": results.get("targets_count")
                }
            )
            self.db.add(snapshot)
            
            logger.info(f"Nuclei scan completed: {len(findings)} findings")
            return events, snapshot

        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}", exc_info=True)
            self.errors.append(f"Nuclei scan failed: {str(e)}")
            return [], None
