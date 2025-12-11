"""
Scans API endpoints
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import List

from app.db import get_db
from app.models import Project, ScanLog, Snapshot, SnapshotType, Event, EventType, SeverityLevel, User
from app.schemas import ScanRequest, ScanResponse
from app.services.orchestrator import ScanOrchestrator
from app.services.notifiers.base import NotificationManager
from app.services.notifiers.slack import SlackNotifier
from app.services.notifiers.discord import DiscordNotifier
from app.services.notifiers.telegram import TelegramNotifier
from app.jobs import get_job_manager
from app.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])


def create_notification_manager(db: Session, project_id: int) -> NotificationManager:
    """Create notification manager for a project"""
    manager = NotificationManager()

    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return manager

    notif_config = project.notification_config or {}

    if notif_config.get("slack", {}).get("enabled", False):
        manager.add_notifier(SlackNotifier(notif_config.get("slack", {})))

    if notif_config.get("discord", {}).get("enabled", False):
        manager.add_notifier(DiscordNotifier(notif_config.get("discord", {})))

    if notif_config.get("telegram", {}).get("enabled", False):
        manager.add_notifier(TelegramNotifier(notif_config.get("telegram", {})))

    return manager


def run_scan_background(project_id: int, mode: str, modules: list = None):
    """Run scan in background thread (fallback when Celery unavailable)"""
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        notification_manager = create_notification_manager(db, project_id)
        orchestrator = ScanOrchestrator(db, notification_manager)
        orchestrator.run_scan(project_id, mode=mode, modules=modules)
    finally:
        db.close()


# Check if Celery is available
CELERY_AVAILABLE = False
try:
    from app.tasks import run_scan_task
    # Test Redis connection
    from app.celery_app import celery_app
    celery_app.control.ping(timeout=1)
    CELERY_AVAILABLE = True
except Exception:
    pass


@router.post("/trigger", response_model=ScanResponse)
def trigger_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Trigger a scan for a project
    Uses Celery worker if available, falls back to BackgroundTasks
    """
    # Validate project exists
    project = db.query(Project).filter(Project.id == scan_request.project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {scan_request.project_id} not found"
        )

    if not project.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Project {scan_request.project_id} is not active"
        )

    # Create initial scan log
    scan_log = ScanLog(
        project_id=scan_request.project_id,
        scan_mode=scan_request.mode,
        status="queued"
    )
    db.add(scan_log)
    db.commit()
    db.refresh(scan_log)

    # Run scan using Celery if available, otherwise fallback to BackgroundTasks
    if CELERY_AVAILABLE:
        try:
            from app.tasks import run_scan_task
            task = run_scan_task.delay(
                scan_request.project_id,
                scan_request.mode,
                scan_request.modules
            )
            logger.info(f"Scan queued via Celery: task_id={task.id}")
        except Exception as e:
            logger.warning(f"Celery failed, using BackgroundTasks: {e}")
            background_tasks.add_task(
                run_scan_background,
                scan_request.project_id,
                scan_request.mode,
                scan_request.modules
            )
    else:
        logger.info("Celery not available, using BackgroundTasks")
        background_tasks.add_task(
            run_scan_background,
            scan_request.project_id,
            scan_request.mode,
            scan_request.modules
        )

    return ScanResponse(
        scan_id=scan_log.id,
        project_id=scan_request.project_id,
        mode=scan_request.mode,
        status="queued",
        events_generated=0,
        started_at=scan_log.started_at
    )


@router.get("/logs", response_model=List[dict])
def get_scan_logs(
    project_id: int = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan logs"""
    query = db.query(ScanLog)

    if project_id:
        query = query.filter(ScanLog.project_id == project_id)

    logs = query.order_by(ScanLog.started_at.desc()).limit(limit).all()

    return [
        {
            "id": log.id,
            "project_id": log.project_id,
            "scan_mode": log.scan_mode,
            "status": log.status,
            "started_at": log.started_at,
            "completed_at": log.completed_at,
            "events_generated": log.events_generated,
            "errors": log.errors,
            "tools_executed": log.tools_executed
        }
        for log in logs
    ]


@router.get("/logs/{scan_id}", response_model=dict)
def get_scan_log(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get specific scan log"""
    log = db.query(ScanLog).filter(ScanLog.id == scan_id).first()

    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan log {scan_id} not found"
        )

    return {
        "id": log.id,
        "project_id": log.project_id,
        "scan_mode": log.scan_mode,
        "status": log.status,
        "started_at": log.started_at,
        "completed_at": log.completed_at,
        "events_generated": log.events_generated,
        "errors": log.errors,
        "tools_executed": log.tools_executed
    }


@router.get("/scheduled")
def get_scheduled_scans(current_user: User = Depends(get_current_user)):
    """Get all scheduled scan jobs"""
    job_manager = get_job_manager()
    return job_manager.get_scheduled_jobs()


@router.post("/schedule")
def schedule_scan(
    project_id: int,
    cron_expression: str,
    scan_mode: str = "normal",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Schedule a recurring scan

    Args:
        project_id: Project ID
        cron_expression: Cron expression (e.g., "0 2 * * *" for daily at 2 AM)
        scan_mode: Scan mode ("normal" or "weekly")
    """
    # Validate project
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )

    # Add scheduled job
    job_manager = get_job_manager()
    job_id = f"scan_project_{project_id}_{scan_mode}"

    try:
        job_manager.add_scan_job(
            project_id=project_id,
            cron_expression=cron_expression,
            scan_mode=scan_mode,
            job_id=job_id
        )

        return {
            "success": True,
            "job_id": job_id,
            "cron_expression": cron_expression,
            "message": f"Scan scheduled successfully"
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to schedule scan: {str(e)}"
        )


@router.put("/schedule/{job_id}")
def update_schedule(
    job_id: str,
    cron_expression: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update an existing scheduled scan job

    Args:
        job_id: Job ID (e.g., "scan_project_1_normal")
        cron_expression: New cron expression (e.g., "0 2 * * *")
    """
    job_manager = get_job_manager()

    # Check if job exists
    existing_job = job_manager.scheduler.get_job(job_id)
    if not existing_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found"
        )

    # Extract project_id and scan_mode from job_id
    # Format: scan_project_{project_id}_{scan_mode}
    try:
        parts = job_id.split('_')
        if len(parts) < 4 or parts[0] != 'scan' or parts[1] != 'project':
            raise ValueError("Invalid job_id format")

        project_id = int(parts[2])
        scan_mode = parts[3] if len(parts) > 3 else 'normal'

        # Validate project exists
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Project {project_id} not found"
            )

        # Update the schedule by adding job with same ID (will replace)
        job_manager.add_scan_job(
            project_id=project_id,
            cron_expression=cron_expression,
            scan_mode=scan_mode,
            job_id=job_id
        )

        # Update project config to store the new schedule
        config = project.config.copy() if project.config else {}
        if 'schedule' not in config:
            config['schedule'] = {}

        config['schedule'][scan_mode] = cron_expression
        config['schedule'][f'{scan_mode}_enabled'] = True  # Also mark as enabled
        project.config = config
        
        # Mark as modified to ensure SQLAlchemy detects the change
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(project, 'config')
        db.commit()

        return {
            "success": True,
            "job_id": job_id,
            "cron_expression": cron_expression,
            "message": "Schedule updated successfully"
        }

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid job_id format: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to update schedule: {str(e)}"
        )


@router.delete("/schedule/{job_id}")
def unschedule_scan(job_id: str, current_user: User = Depends(get_current_user)):
    """Remove a scheduled scan job"""
    job_manager = get_job_manager()

    try:
        job_manager.remove_scan_job(job_id)
        return {"success": True, "message": f"Job {job_id} removed"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found"
        )


def run_nuclei_scan_background(project_id: int):
    """Run Nuclei scan in background"""
    from app.db import SessionLocal
    from app.services.scanner.nuclei import NucleiScanner
    from datetime import datetime
    
    db = SessionLocal()
    scan_log = None
    try:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            return
        
        # Create ScanLog entry
        scan_log = ScanLog(
            project_id=project_id,
            scan_mode="nuclei",
            status="running",
            started_at=datetime.utcnow()
        )
        db.add(scan_log)
        db.commit()
        db.refresh(scan_log)
        
        config = project.config or {}
        enabled_tools = config.get("enabled_tools", {})
        nuclei_config = enabled_tools.get("nuclei", {})
        
        # Force enable for on-demand scan
        nuclei_config["enabled"] = True
        
        # Get alive hosts from HTTP snapshot
        http_snapshot = db.query(Snapshot).filter(
            Snapshot.project_id == project_id,
            Snapshot.type == SnapshotType.HTTP
        ).order_by(Snapshot.created_at.desc()).first()
        
        if not http_snapshot:
            if scan_log:
                scan_log.status = "failed"
                scan_log.completed_at = datetime.utcnow()
                scan_log.errors = ["No HTTP snapshot available - run HTTP scan first"]
                db.commit()
            return
        
        http_records = http_snapshot.data.get("http_records", {})
        targets = []
        
        # Debug logging
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Nuclei scan: Found {len(http_records)} HTTP records in snapshot")
        
        scan_alive_only = nuclei_config.get("scan_alive_only", True)
        logger.info(f"Nuclei scan: scan_alive_only={scan_alive_only}")
        
        # Log sample records for debugging
        sample_count = 0
        for url, data in http_records.items():
            status_code = data.get("status_code", 0)
            if sample_count < 5:
                logger.info(f"Nuclei scan: Sample record - URL: {url}, status_code: {status_code}")
                sample_count += 1
            
            if scan_alive_only and status_code and 200 <= status_code < 400:
                targets.append(url)
            elif not scan_alive_only:
                targets.append(url)
        
        logger.info(f"Nuclei scan: {len(targets)} targets passed filter")
        
        if not targets:
            if scan_log:
                scan_log.status = "completed"
                scan_log.completed_at = datetime.utcnow()
                scan_log.events_generated = 0
                scan_log.errors = [f"No targets found: {len(http_records)} HTTP records, 0 passed filter (alive_only={scan_alive_only})"]
                db.commit()
            return
        
        # Run scan
        scanner = NucleiScanner(project_id, nuclei_config)
        results = scanner.scan(targets)
        
        if results.get("error"):
            if scan_log:
                scan_log.status = "failed"
                scan_log.completed_at = datetime.utcnow()
                scan_log.errors = [results.get("error")]
                db.commit()
            return
        
        findings = results.get("findings", [])
        stats = results.get("stats", {})
        
        # Save snapshot
        snapshot = Snapshot(
            project_id=project_id,
            type=SnapshotType.NUCLEI,
            data={
                "nuclei_findings": findings,
                "stats": stats,
                "scanned_at": results.get("scanned_at"),
                "targets_count": results.get("targets_count")
            }
        )
        db.add(snapshot)
        
        # Create events for findings
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO
        }
        
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            event = Event(
                project_id=project_id,
                type=EventType.VULNERABILITY_FOUND,
                severity=severity_map.get(severity, SeverityLevel.INFO),
                summary=f"Nuclei: {finding.get('template_name', 'Unknown')} on {finding.get('host', 'unknown')}",
                details={
                    "template_id": finding.get("template_id"),
                    "template_name": finding.get("template_name"),
                    "matched_at": finding.get("matched_at"),
                    "severity": severity,
                    "description": finding.get("description"),
                    "source": "nuclei"
                },
                related_entities={
                    "host": finding.get("host"),
                    "template_id": finding.get("template_id")
                }
            )
            db.add(event)
        
        # Update ScanLog
        if scan_log:
            scan_log.status = "completed"
            scan_log.completed_at = datetime.utcnow()
            scan_log.events_generated = len(findings)
        
        db.commit()
        
    except Exception as e:
        if scan_log:
            scan_log.status = "failed"
            scan_log.completed_at = datetime.utcnow()
            scan_log.errors = [str(e)]
            db.commit()
    finally:
        db.close()



@router.post("/nuclei/{project_id}")
def trigger_nuclei_scan(
    project_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Trigger an on-demand Nuclei vulnerability scan
    
    Args:
        project_id: Project ID to scan
    """
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )
    
    # Check if nuclei is available
    from app.config import settings
    import shutil
    
    if not shutil.which(settings.nuclei_path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nuclei is not installed or not found in PATH"
        )
    
    # Queue background task
    background_tasks.add_task(run_nuclei_scan_background, project_id)
    
    return {
        "success": True,
        "message": f"Nuclei scan queued for project {project.name}",
        "project_id": project_id
    }
