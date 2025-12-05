"""
Dashboard and UI endpoints
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional

from app.db import get_db
from app.models import Project, Event, Snapshot, ScanLog, SeverityLevel, User
from app.schemas import DashboardStats, ProjectStats
from app.config import settings
from app.auth import get_current_user

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="web/templates")


@router.get("/", response_class=HTMLResponse)
def dashboard_home(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Main dashboard page"""
    # Get all active projects
    projects = db.query(Project).filter(Project.is_active == True).all()

    # Get today's events
    today = datetime.utcnow().date()
    today_events = db.query(Event).filter(
        Event.created_at >= today
    ).all()

    # Count by severity
    high_severity_count = sum(
        1 for e in today_events
        if e.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    )

    # Get recent scan logs
    recent_scans = db.query(ScanLog).order_by(
        ScanLog.started_at.desc()
    ).limit(10).all()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "current_user": current_user,
        "projects": projects,
        "total_projects": len(projects),
        "total_events_today": len(today_events),
        "high_severity_events": high_severity_count,
        "recent_scans": recent_scans
    })


@router.get("/projects/new", response_class=HTMLResponse)
def project_new(request: Request, current_user: User = Depends(get_current_user)):
    """Create new project page"""
    return templates.TemplateResponse("project_new.html", {
        "request": request,
        "current_user": current_user
    })


@router.get("/projects/{project_id}", response_class=HTMLResponse)
def project_detail(
    request: Request,
    project_id: int,
    page: int = 1,
    per_page: int = 50,
    search: str = "",
    exclude: str = "",
    status_filter: str = "",
    tech_filter: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Project detail page with server-side pagination for assets"""
    project = db.query(Project).filter(Project.id == project_id).first()

    if not project:
        return templates.TemplateResponse("404.html", {
            "request": request,
        "current_user": current_user,
            "message": f"Project {project_id} not found"
        }, status_code=404)

    # Get latest snapshots (skip endpoints on initial load for performance)
    # Endpoints can be very large (100+ MB) and will be loaded via AJAX
    latest_snapshots = {}
    for snap_type in ["subdomains", "dns", "http", "shodan"]:
        snapshot = db.query(Snapshot).filter(
            Snapshot.project_id == project_id,
            Snapshot.type == snap_type
        ).order_by(Snapshot.created_at.desc()).first()

        if snapshot:
            latest_snapshots[snap_type] = snapshot

    # Server-side pagination for All Assets
    all_subdomains = []
    total_subdomains = 0
    paginated_subdomains = []
    total_pages = 1
    showing_start = 0
    showing_end = 0

    if "subdomains" in latest_snapshots:
        all_subdomains = sorted(latest_snapshots["subdomains"].data.get("subdomains", []))

        # Apply filters
        filtered_subdomains = []
        dns_data = latest_snapshots.get("dns", {}).data.get("dns_records", {}) if "dns" in latest_snapshots else {}
        http_data = latest_snapshots.get("http", {}).data.get("http_records", {}) if "http" in latest_snapshots else {}

        # Parse exclude patterns
        exclude_patterns = [p.strip().lower() for p in exclude.split(",") if p.strip()]

        for subdomain in all_subdomains:
            # Check exclude patterns
            if exclude_patterns:
                should_exclude = False
                for pattern in exclude_patterns:
                    if pattern in subdomain.lower():
                        should_exclude = True
                        break
                if should_exclude:
                    continue

            # Get related data
            dns_record = dns_data.get(subdomain, {})
            http_url_https = f"https://{subdomain}"
            http_url_http = f"http://{subdomain}"
            http_record = http_data.get(http_url_https) or http_data.get(http_url_http, {})

            # Apply search filter
            if search:
                search_lower = search.lower()
                matches_search = (
                    search_lower in subdomain.lower() or
                    search_lower in http_record.get("title", "").lower() or
                    search_lower in str(dns_record.get("a", [])).lower() or
                    search_lower in str(dns_record.get("cname", [])).lower() or
                    search_lower in str(http_record.get("technologies", [])).lower()
                )
                if not matches_search:
                    continue

            # Apply status filter
            if status_filter:
                status_code = http_record.get("status_code", "")
                if not str(status_code).startswith(status_filter):
                    continue

            # Apply technology filter
            if tech_filter:
                technologies = http_record.get("technologies", [])
                tech_str = ",".join(technologies).lower() if isinstance(technologies, list) else str(technologies).lower()
                if tech_filter.lower() not in tech_str:
                    continue

            filtered_subdomains.append(subdomain)

        # Calculate pagination
        total_subdomains = len(filtered_subdomains)
        total_pages = max(1, (total_subdomains + per_page - 1) // per_page)
        page = max(1, min(page, total_pages))  # Clamp page number

        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, total_subdomains)
        paginated_subdomains = filtered_subdomains[start_idx:end_idx]

        # Calculate display indices (1-based)
        showing_start = start_idx + 1 if total_subdomains > 0 else 0
        showing_end = end_idx

    # Get recent events (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_events = db.query(Event).filter(
        Event.project_id == project_id,
        Event.created_at >= week_ago
    ).order_by(Event.created_at.desc()).limit(50).all()

    # Get recent scans
    recent_scans = db.query(ScanLog).filter(
        ScanLog.project_id == project_id
    ).order_by(ScanLog.started_at.desc()).limit(10).all()

    return templates.TemplateResponse("project_detail.html", {
        "request": request,
        "current_user": current_user,
        "project": project,
        "latest_snapshots": latest_snapshots,
        "recent_events": recent_events,
        "recent_scans": recent_scans,
        # Pagination data
        "paginated_subdomains": paginated_subdomains,
        "current_page": page,
        "per_page": per_page,
        "total_subdomains": total_subdomains,
        "total_pages": total_pages,
        "showing_start": showing_start,
        "showing_end": showing_end,
        "showing_end": showing_end,
        "search": search,
        "exclude": exclude,
        "status_filter": status_filter,
        "tech_filter": tech_filter
    })


@router.get("/projects/{project_id}/edit", response_class=HTMLResponse)
def project_edit(
    request: Request,
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Project edit page"""
    project = db.query(Project).filter(Project.id == project_id).first()

    if not project:
        return templates.TemplateResponse("404.html", {
            "request": request,
        "current_user": current_user,
            "message": f"Project {project_id} not found"
        }, status_code=404)

    return templates.TemplateResponse("project_edit.html", {
        "request": request,
        "current_user": current_user,
        "project": project
    })


@router.get("/events", response_class=HTMLResponse)
def events_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Events list page - uses AJAX for data loading"""
    # Get all active projects for filter dropdown
    projects = db.query(Project).filter(Project.is_active == True).all()

    # Get quick stats (count only, no full data loading)
    cutoff = datetime.utcnow() - timedelta(days=30)
    total_events = db.query(Event).filter(Event.created_at >= cutoff).count()
    vuln_count = db.query(Event).filter(
        Event.created_at >= cutoff,
        Event.type == 'vulnerability_found'
    ).count()
    port_count = db.query(Event).filter(
        Event.created_at >= cutoff,
        Event.type == 'port_new'
    ).count()
    dns_count = db.query(Event).filter(
        Event.created_at >= cutoff,
        Event.type == 'dns_changed'
    ).count()

    return templates.TemplateResponse("events.html", {
        "request": request,
        "current_user": current_user,
        "projects": projects,
        "total_events": total_events,
        "vuln_count": vuln_count,
        "port_count": port_count,
        "dns_count": dns_count
    })


@router.get("/api/events")
def get_events_paginated(
    page: int = 1,
    per_page: int = 50,
    search: str = "",
    project_id: Optional[int] = None,
    severity: str = "",
    event_type: str = "",
    acknowledged: str = "",
    sort_order: str = "desc",
    days: int = 30,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get paginated events with server-side filtering"""
    # Build base query
    cutoff = datetime.utcnow() - timedelta(days=days)
    query = db.query(Event).filter(Event.created_at >= cutoff)

    # Apply filters
    if project_id is not None:
        query = query.filter(Event.project_id == project_id)

    if severity:
        query = query.filter(Event.severity == severity.upper())

    if event_type:
        query = query.filter(Event.type == event_type)

    if acknowledged == "acknowledged":
        query = query.filter(Event.acknowledged == True)
    elif acknowledged == "unacknowledged":
        query = query.filter(Event.acknowledged == False)

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(Event.summary.ilike(search_pattern))

    # Sort order
    if sort_order == "asc":
        query = query.order_by(Event.created_at.asc())
    else:
        query = query.order_by(Event.created_at.desc())

    # Get total count before pagination
    total_count = query.count()

    # Apply pagination
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    start_idx = (page - 1) * per_page
    events = query.offset(start_idx).limit(per_page).all()

    # Get project mapping
    project_ids = list(set([e.project_id for e in events]))
    projects = db.query(Project).filter(Project.id.in_(project_ids)).all()
    project_map = {p.id: p.name for p in projects}

    # Convert events to dict
    events_list = []
    for event in events:
        events_list.append({
            "id": event.id,
            "type": event.type.value if hasattr(event.type, 'value') else str(event.type),
            "severity": event.severity.value if hasattr(event.severity, 'value') else str(event.severity),
            "summary": event.summary,
            "project_id": event.project_id,
            "project_name": project_map.get(event.project_id, f"Project {event.project_id}"),
            "created_at": event.created_at.strftime('%Y-%m-%d %H:%M'),
            "acknowledged": event.acknowledged,
            "has_details": event.details is not None
        })

    return {
        "events": events_list,
        "total": total_count,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "showing_start": start_idx + 1 if total_count > 0 else 0,
        "showing_end": min(start_idx + per_page, total_count)
    }


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, current_user: User = Depends(get_current_user)):
    """Settings page"""
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "current_user": current_user,
        "settings": settings
    })


@router.get("/schedules", response_class=HTMLResponse)
def schedules_page(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Scheduled jobs page"""
    from app.jobs import get_job_manager

    # Get all scheduled jobs
    job_manager = get_job_manager()
    scheduled_jobs = job_manager.get_scheduled_jobs()

    # Get all projects for mapping
    projects = db.query(Project).all()
    project_map = {p.id: p for p in projects}

    # Enhance job data with project information
    enhanced_jobs = []
    for job in scheduled_jobs:
        job_data = dict(job)

        # Extract project_id from job_id (format: scan_project_{id}_{mode})
        if job['id'].startswith('scan_project_'):
            parts = job['id'].split('_')
            if len(parts) >= 3:
                try:
                    project_id = int(parts[2])
                    scan_mode = parts[3] if len(parts) > 3 else 'normal'

                    project = project_map.get(project_id)
                    if project:
                        job_data['project'] = project
                        job_data['project_id'] = project_id
                        job_data['scan_mode'] = scan_mode

                        # Get scan config from project
                        config = project.config or {}
                        enabled_tools = config.get('enabled_tools', {})

                        job_data['scan_config'] = {
                            'subdomains': enabled_tools.get('subdomains', {}).get('enabled', True),
                            'dns': enabled_tools.get('dns', {}).get('enabled', True),
                            'http': enabled_tools.get('http', {}).get('enabled', True),
                            'shodan': enabled_tools.get('shodan', {}).get('enabled', False),
                            'endpoints': enabled_tools.get('endpoints', {}).get('enabled', False)
                        }
                except (ValueError, IndexError):
                    pass

        enhanced_jobs.append(job_data)

    return templates.TemplateResponse("schedules.html", {
        "request": request,
        "current_user": current_user,
        "jobs": enhanced_jobs
    })


@router.get("/api/projects/{project_id}/endpoints")
def get_project_endpoints(
    project_id: int,
    page: int = 1,
    per_page: int = 100,
    search: str = "",
    exclude: str = "",
    category: str = "",
    status: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get paginated endpoints for a project (AJAX endpoint)"""
    # Get latest endpoints snapshot
    endpoint_snapshot = db.query(Snapshot).filter(
        Snapshot.project_id == project_id,
        Snapshot.type == "endpoints"
    ).order_by(Snapshot.created_at.desc()).first()

    if not endpoint_snapshot:
        return {
            "endpoints": [],
            "total": 0,
            "page": page,
            "per_page": per_page,
            "total_pages": 0,
            "showing_start": 0,
            "showing_end": 0,
            "has_data": False
        }

    # Get enriched URLs if available, fallback to plain URLs
    enriched_urls = endpoint_snapshot.data.get("enriched_urls", [])
    plain_urls = endpoint_snapshot.data.get("urls", [])
    js_files = set(endpoint_snapshot.data.get("js_files", []))

    # Build endpoint list
    if enriched_urls:
        # Use list comprehension for speed
        all_endpoints = [
            {
                "url": e.get("url", ""),
                "status_code": e.get("status_code"),
                "title": e.get("title", ""),
                "categories": e.get("categories", []),
                "is_sensitive": e.get("is_sensitive", False)
            }
            for e in enriched_urls
            if e.get("url", "") not in js_files
        ]
    else:
        all_endpoints = [
            {
                "url": url,
                "status_code": None,
                "title": "",
                "categories": [],
                "is_sensitive": False
            }
            for url in plain_urls
            if url not in js_files
        ]

    # Parse inputs
    search_lower = search.lower() if search else ""
    exclude_patterns = [p.strip().lower() for p in exclude.split(",") if p.strip()]
    
    # OPTIMIZATION: If no filters are active, skip the filtering loop
    if not (search or exclude or category or status):
         filtered_endpoints = all_endpoints
    else:
        filtered_endpoints = []
        for endpoint in all_endpoints:
            # Check exclude patterns
            if exclude_patterns:
                should_exclude = False
                for pattern in exclude_patterns:
                    if pattern in endpoint["url"].lower():
                        should_exclude = True
                        break
                if should_exclude:
                    continue

            # Search filter
            if search:
                title = endpoint.get("title")
                title_lower = title.lower() if title else ""
                
                if not (search_lower in endpoint["url"].lower() or
                        search_lower in title_lower):
                    continue

            # Category filter
            if category:
                if category == "sensitive" and not endpoint.get("is_sensitive"):
                    continue
                # Add check for specific category names if needed
                elif category != "sensitive":
                     categories = [c['name'] for c in endpoint.get("categories", [])]
                     if category not in categories:
                         continue

            # Status filter
            if status:
                status_code = endpoint.get("status_code")
                if status == "active" and (not status_code or status_code >= 400):
                    continue
                elif status == "error" and (not status_code or status_code < 400):
                    continue
                elif status == "300" and (not status_code or not (300 <= status_code < 400)):
                    continue
                elif status == "400" and (not status_code or not (400 <= status_code < 500)):
                    continue
                elif status == "500" and (not status_code or status_code < 500):
                    continue
                elif status == "none" and status_code is not None:
                    continue

            filtered_endpoints.append(endpoint)

    # Calculate pagination
    total_endpoints = len(filtered_endpoints)
    total_pages = max(1, (total_endpoints + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    start_idx = (page - 1) * per_page
    end_idx = min(start_idx + per_page, total_endpoints)
    paginated_endpoints = filtered_endpoints[start_idx:end_idx]


    return {
        "endpoints": paginated_endpoints,
        "total": total_endpoints,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "showing_start": start_idx + 1 if total_endpoints > 0 else 0,
        "showing_end": end_idx,
        "has_data": True,
        "snapshot_date": endpoint_snapshot.created_at.isoformat() if endpoint_snapshot else None
    }


@router.get("/api/projects/{project_id}/jsfiles")
def get_project_jsfiles(
    project_id: int,
    page: int = 1,
    per_page: int = 100,
    search: str = "",
    exclude: str = "",
    status_filter: str = "",
    secrets_filter: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get paginated JS files for a project (AJAX endpoint)"""
    # Get latest endpoints snapshot
    endpoint_snapshot = db.query(Snapshot).filter(
        Snapshot.project_id == project_id,
        Snapshot.type == "endpoints"
    ).order_by(Snapshot.created_at.desc()).first()

    if not endpoint_snapshot:
        return {
            "js_files": [],
            "total": 0,
            "page": page,
            "per_page": per_page,
            "total_pages": 0,
            "showing_start": 0,
            "showing_end": 0,
            "has_data": False
        }

    js_files_list = endpoint_snapshot.data.get("js_files", [])
    js_file_analysis = endpoint_snapshot.data.get("js_file_analysis", {})

    # Build JS files list with analysis
    all_js_files = []
    for js_file in js_files_list:
        analysis = js_file_analysis.get(js_file, {})
        is_active = analysis.get("status", "unknown") == "active"
        secrets_info = analysis.get("secrets", {})

        all_js_files.append({
            "url": js_file,
            "status": "active" if is_active else ("inactive" if analysis else "unknown"),
            "status_code": analysis.get("status_code"),
            "secrets": secrets_info,
            "has_secrets": secrets_info.get("has_secrets", False),
            "risk_level": secrets_info.get("risk_level", "unknown")
        })

    # Apply filters
    filtered_js_files = []
    # Parse exclude patterns
    exclude_patterns = [p.strip().lower() for p in exclude.split(",") if p.strip()]

    for js_file in all_js_files:
        # Check exclude patterns
        if exclude_patterns:
            should_exclude = False
            for pattern in exclude_patterns:
                if pattern in js_file["url"].lower():
                    should_exclude = True
                    break
            if should_exclude:
                continue

        # Search filter
        if search:
            if search.lower() not in js_file["url"].lower():
                continue

        # Status filter
        if status_filter:
            if js_file["status"] != status_filter:
                continue

        # Secrets filter
        if secrets_filter:
            if secrets_filter == "suspicious" and not js_file["has_secrets"]:
                continue
            elif secrets_filter == "clean" and js_file["has_secrets"]:
                continue

        filtered_js_files.append(js_file)

    # Calculate pagination
    total_js_files = len(filtered_js_files)
    total_pages = max(1, (total_js_files + per_page - 1) // per_page)
    page = max(1, min(page, total_pages))

    start_idx = (page - 1) * per_page
    end_idx = min(start_idx + per_page, total_js_files)
    paginated_js_files = filtered_js_files[start_idx:end_idx]

    # Count secrets
    secrets_count = sum(1 for jf in all_js_files if jf["has_secrets"])

    return {
        "js_files": paginated_js_files,
        "total": total_js_files,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "showing_start": start_idx + 1 if total_js_files > 0 else 0,
        "showing_end": end_idx,
        "has_data": True,
        "secrets_count": secrets_count,
        "snapshot_date": endpoint_snapshot.created_at.isoformat() if endpoint_snapshot else None
    }


@router.get("/api/projects/{project_id}/takeovers")
def get_project_takeovers(
    project_id: int,
    page: int = 1,
    per_page: int = 50,
    search: str = "",
    severity: str = "",
    service: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get paginated takeover findings for a project (AJAX endpoint)"""
    # Verify project access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return {"has_data": False, "takeovers": [], "total": 0}

    # Get latest DNS snapshot
    dns_snapshot = db.query(Snapshot).filter(
        Snapshot.project_id == project_id,
        Snapshot.type == "DNS"
    ).order_by(Snapshot.created_at.desc()).first()

    if not dns_snapshot or not dns_snapshot.scan_metadata:
        return {
            "takeovers": [],
            "total": 0,
            "page": page,
            "per_page": per_page,
            "total_pages": 0,
            "showing_start": 0,
            "showing_end": 0,
            "has_data": False,
            "snapshot_date": None
        }

    # Get takeover findings from metadata
    all_takeovers = dns_snapshot.scan_metadata.get("takeover_findings", [])

    # Filter by search
    if search:
        search_lower = search.lower()
        all_takeovers = [
            t for t in all_takeovers
            if search_lower in t.get("subdomain", "").lower() or
               search_lower in t.get("cname", "").lower()
        ]

    # Filter by severity
    if severity:
        all_takeovers = [
            t for t in all_takeovers
            if t.get("severity", "").lower() == severity.lower()
        ]

    # Filter by service
    if service:
        all_takeovers = [
            t for t in all_takeovers
            if t.get("service", "").lower() == service.lower()
        ]

    # Pagination
    total_takeovers = len(all_takeovers)
    total_pages = (total_takeovers + per_page - 1) // per_page if total_takeovers > 0 else 0

    start_idx = (page - 1) * per_page
    end_idx = min(start_idx + per_page, total_takeovers)

    paginated_takeovers = all_takeovers[start_idx:end_idx]

    # Get unique services for filter dropdown
    unique_services = sorted(list(set(t.get("service", "unknown") for t in all_takeovers)))

    return {
        "takeovers": paginated_takeovers,
        "total": total_takeovers,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "showing_start": start_idx + 1 if total_takeovers > 0 else 0,
        "showing_end": end_idx,
        "has_data": True,
        "snapshot_date": dns_snapshot.created_at.isoformat(),
        "unique_services": unique_services
    }


@router.get("/api/projects/{project_id}/events")
def get_project_events(
    project_id: int,
    page: int = 1,
    per_page: int = 50,
    search: str = "",
    exclude: str = "",
    severity: str = "",
    event_type: str = "",
    days: int = 7,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get paginated events for a project (AJAX endpoint)"""
    # Verify project access
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return {"has_data": False, "events": [], "total": 0}

    # Build query
    query = db.query(Event).filter(Event.project_id == project_id)

    # Filter by days
    if days > 0:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(Event.created_at >= cutoff_date)

    # Filter by severity
    if severity:
        query = query.filter(Event.severity == severity)

    # Filter by type
    if event_type:
        query = query.filter(Event.type == event_type)

    # Filter by search
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(Event.summary.ilike(search_pattern))

    # Exclude patterns (negative filter)
    if exclude:
        patterns = [p.strip() for p in exclude.split(",") if p.strip()]
        for pattern in patterns:
            query = query.filter(~Event.summary.ilike(f"%{pattern}%"))

    # Order by most recent
    query = query.order_by(Event.created_at.desc())

    # Get total count
    total_events = query.count()

    # Pagination
    total_pages = (total_events + per_page - 1) // per_page if total_events > 0 else 0
    start_idx = (page - 1) * per_page
    end_idx = min(start_idx + per_page, total_events)

    paginated_events = query.offset(start_idx).limit(per_page).all()

    # Convert to dict
    events_list = []
    for event in paginated_events:
        events_list.append({
            "id": event.id,
            "type": event.type.value if hasattr(event.type, 'value') else str(event.type),
            "severity": event.severity.value if hasattr(event.severity, 'value') else str(event.severity),
            "summary": event.summary,
            "details": event.details,
            "created_at": event.created_at.isoformat(),
            "related_entities": event.related_entities
        })

    # Get unique event types for filter
    unique_types = db.query(Event.type).filter(Event.project_id == project_id).distinct().all()
    unique_types = [t[0].value if hasattr(t[0], 'value') else str(t[0]) for t in unique_types]

    # Count by severity
    severity_counts = {
        "CRITICAL": query.filter(Event.severity == "CRITICAL").count(),
        "HIGH": query.filter(Event.severity == "HIGH").count(),
        "MEDIUM": query.filter(Event.severity == "MEDIUM").count(),
        "LOW": query.filter(Event.severity == "LOW").count(),
        "INFO": query.filter(Event.severity == "INFO").count()
    }

    return {
        "events": events_list,
        "total": total_events,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "showing_start": start_idx + 1 if total_events > 0 else 0,
        "showing_end": end_idx,
        "has_data": True,
        "unique_types": unique_types,
        "severity_counts": severity_counts
    }


@router.get("/api/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get dashboard statistics (API endpoint for AJAX)"""
    projects = db.query(Project).filter(Project.is_active == True).all()

    today = datetime.utcnow().date()
    today_events = db.query(Event).filter(Event.created_at >= today).all()

    high_severity = sum(
        1 for e in today_events
        if e.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    )

    # Get project stats
    project_stats = []
    for project in projects:
        # Count subdomains from latest snapshot
        subdomain_snapshot = db.query(Snapshot).filter(
            Snapshot.project_id == project.id,
            Snapshot.type == "subdomains"
        ).order_by(Snapshot.created_at.desc()).first()

        subdomain_count = 0
        if subdomain_snapshot:
            subdomain_count = len(subdomain_snapshot.data.get("subdomains", []))

        # Count endpoints (without loading full data)
        endpoint_snapshot = db.query(Snapshot).filter(
            Snapshot.project_id == project.id,
            Snapshot.type == "endpoints"
        ).order_by(Snapshot.created_at.desc()).first()

        endpoint_count = 0
        if endpoint_snapshot:
            endpoint_count = len(endpoint_snapshot.data.get("urls", []))

        # Recent events (7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_events = db.query(Event).filter(
            Event.project_id == project.id,
            Event.created_at >= week_ago
        ).all()

        high_sev_events = sum(
            1 for e in recent_events
            if e.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        )

        project_stats.append(ProjectStats(
            project_id=project.id,
            project_name=project.name,
            total_domains=len(project.domains),
            total_subdomains=subdomain_count,
            total_endpoints=endpoint_count,
            last_scan_at=project.last_scan_at,
            recent_events_count=len(recent_events),
            high_severity_events=high_sev_events
        ))

    return DashboardStats(
        total_projects=len(projects),
        active_projects=len(projects),
        total_events_today=len(today_events),
        high_severity_events_today=high_severity,
        last_scan=max([p.last_scan_at for p in projects if p.last_scan_at], default=None),
        projects=project_stats
    )
