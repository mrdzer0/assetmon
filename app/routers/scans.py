"""
Scans API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import List

from app.db import get_db
from app.models import Project, ScanLog
from app.schemas import ScanRequest, ScanResponse
from app.services.orchestrator import ScanOrchestrator
from app.services.notifiers.base import NotificationManager
from app.services.notifiers.slack import SlackNotifier
from app.services.notifiers.discord import DiscordNotifier
from app.services.notifiers.telegram import TelegramNotifier
from app.jobs import get_job_manager

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


def run_scan_background(project_id: int, mode: str):
    """Run scan in background"""
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        notification_manager = create_notification_manager(db, project_id)
        orchestrator = ScanOrchestrator(db, notification_manager)
        orchestrator.run_scan(project_id, mode=mode)
    finally:
        db.close()


@router.post("/trigger", response_model=ScanResponse)
def trigger_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Trigger a scan for a project
    The scan runs in the background
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

    # Run scan in background
    background_tasks.add_task(
        run_scan_background,
        scan_request.project_id,
        scan_request.mode
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
    db: Session = Depends(get_db)
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
def get_scan_log(scan_id: int, db: Session = Depends(get_db)):
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
def get_scheduled_scans():
    """Get all scheduled scan jobs"""
    job_manager = get_job_manager()
    return job_manager.get_scheduled_jobs()


@router.post("/schedule")
def schedule_scan(
    project_id: int,
    cron_expression: str,
    scan_mode: str = "normal",
    db: Session = Depends(get_db)
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


@router.delete("/schedule/{job_id}")
def unschedule_scan(job_id: str):
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
