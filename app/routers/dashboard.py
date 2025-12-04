"""
Dashboard and UI endpoints
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

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

    # Get latest snapshots
    latest_snapshots = {}
    for snap_type in ["subdomains", "dns", "http", "shodan", "endpoints"]:
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

    if "subdomains" in latest_snapshots:
        all_subdomains = sorted(latest_snapshots["subdomains"].data.get("subdomains", []))

        # Apply filters
        filtered_subdomains = []
        dns_data = latest_snapshots.get("dns", {}).data.get("dns_records", {}) if "dns" in latest_snapshots else {}
        http_data = latest_snapshots.get("http", {}).data.get("http_records", {}) if "http" in latest_snapshots else {}

        for subdomain in all_subdomains:
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
        "search": search,
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
    """Events list page"""
    # Get all events (last 30 days)
    cutoff = datetime.utcnow() - timedelta(days=30)
    events = db.query(Event).filter(
        Event.created_at >= cutoff
    ).order_by(Event.created_at.desc()).all()

    # Get all active projects
    projects = db.query(Project).filter(Project.is_active == True).all()

    # Create project ID to name mapping
    project_map = {p.id: p.name for p in projects}

    return templates.TemplateResponse("events.html", {
        "request": request,
        "current_user": current_user,
        "events": events,
        "projects": projects,
        "project_map": project_map
    })


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

        # Count endpoints
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
