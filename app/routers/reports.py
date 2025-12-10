"""
Reports API endpoints
Generate PDF and HTML reports for projects
Supports async generation for large reports to avoid timeout
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from fastapi.responses import StreamingResponse, HTMLResponse, FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional, Dict
from pydantic import BaseModel
from datetime import datetime
import io
import os
import uuid
import json
import logging
import threading
import time

from app.db import get_db, SessionLocal
from app.models import Project, ScanLog, Snapshot, SnapshotType, Event
from app.services.report_generator import ReportGenerator

router = APIRouter(prefix="/api/reports", tags=["reports"])
logger = logging.getLogger(__name__)

# In-memory storage for report job status (could use Redis for production)
report_jobs: Dict[str, dict] = {}
REPORTS_DIR = "/tmp/assetmon_reports"

# Ensure reports directory exists
os.makedirs(REPORTS_DIR, exist_ok=True)


class ReportSections(BaseModel):
    executive_summary: bool = True
    subdomains: bool = True
    dns_records: bool = True
    http_endpoints: bool = True
    vulnerabilities: bool = True
    scan_history: bool = True


class CompanyInfo(BaseModel):
    name: str = ""
    website: str = ""
    email: str = ""


class ReportRequest(BaseModel):
    project_ids: List[int]
    format: str = "pdf"  # "pdf" or "html"
    sections: ReportSections = ReportSections()
    company: CompanyInfo = CompanyInfo()


def cleanup_old_reports():
    """Remove reports older than 1 hour"""
    try:
        now = time.time()
        for filename in os.listdir(REPORTS_DIR):
            filepath = os.path.join(REPORTS_DIR, filename)
            if os.path.isfile(filepath):
                # Remove files older than 1 hour
                if now - os.path.getmtime(filepath) > 3600:
                    os.remove(filepath)
                    logger.info(f"Cleaned up old report: {filename}")
    except Exception as e:
        logger.error(f"Error cleaning up reports: {e}")


def generate_report_task(
    job_id: str,
    project_ids: List[int],
    format: str,
    sections: dict,
    company: dict
):
    """Background task to generate report"""
    try:
        # Update job status
        report_jobs[job_id]["status"] = "processing"
        report_jobs[job_id]["started_at"] = datetime.utcnow().isoformat()
        
        # Create new database session for background task
        db = SessionLocal()
        
        try:
            # Fetch projects
            projects = db.query(Project).filter(Project.id.in_(project_ids)).all()
            if not projects:
                report_jobs[job_id]["status"] = "failed"
                report_jobs[job_id]["error"] = "No projects found"
                return
            
            # Generate report
            generator = ReportGenerator(db)
            
            if format.lower() == "html":
                content = generator.generate_html_report(
                    projects=projects,
                    sections=sections,
                    company=company
                )
                filename = f"report_{job_id}.html"
                filepath = os.path.join(REPORTS_DIR, filename)
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
            else:
                # PDF format
                pdf_bytes = generator.generate_pdf_report(
                    projects=projects,
                    sections=sections,
                    company=company
                )
                filename = f"report_{job_id}.pdf"
                filepath = os.path.join(REPORTS_DIR, filename)
                with open(filepath, "wb") as f:
                    f.write(pdf_bytes)
            
            # Update job status
            report_jobs[job_id]["status"] = "completed"
            report_jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
            report_jobs[job_id]["filename"] = filename
            report_jobs[job_id]["filepath"] = filepath
            
            logger.info(f"Report job {job_id} completed: {filename}")
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Report generation failed for job {job_id}: {e}")
        report_jobs[job_id]["status"] = "failed"
        report_jobs[job_id]["error"] = str(e)


@router.post("/generate")
def generate_report(
    request: ReportRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Start async report generation
    
    Returns immediately with a job_id that can be used to check status
    and download the report when ready.
    """
    # Validate projects exist
    projects = db.query(Project).filter(Project.id.in_(request.project_ids)).all()
    if not projects:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No projects found with the given IDs"
        )
    
    # Create job ID
    job_id = str(uuid.uuid4())[:8]
    
    # Initialize job status
    report_jobs[job_id] = {
        "status": "queued",
        "created_at": datetime.utcnow().isoformat(),
        "project_ids": request.project_ids,
        "format": request.format,
        "filename": None,
        "error": None
    }
    
    # Cleanup old reports
    background_tasks.add_task(cleanup_old_reports)
    
    # Start report generation in background thread (not blocking)
    thread = threading.Thread(
        target=generate_report_task,
        args=(
            job_id,
            request.project_ids,
            request.format,
            request.sections.model_dump(),
            request.company.model_dump()
        ),
        daemon=True
    )
    thread.start()
    
    logger.info(f"Report job {job_id} queued for projects {request.project_ids}")
    
    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Report generation started. Poll /api/reports/status/{job_id} to check progress."
    }


@router.get("/status/{job_id}")
def get_report_status(job_id: str):
    """
    Check the status of a report generation job
    """
    if job_id not in report_jobs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found"
        )
    
    job = report_jobs[job_id]
    
    return {
        "job_id": job_id,
        "status": job["status"],
        "created_at": job.get("created_at"),
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at"),
        "error": job.get("error"),
        "download_url": f"/api/reports/download/{job_id}" if job["status"] == "completed" else None
    }


@router.get("/download/{job_id}")
def download_report(job_id: str):
    """
    Download a completed report
    """
    if job_id not in report_jobs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found"
        )
    
    job = report_jobs[job_id]
    
    if job["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Report not ready. Current status: {job['status']}"
        )
    
    filepath = job.get("filepath")
    if not filepath or not os.path.exists(filepath):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file not found"
        )
    
    filename = job.get("filename", f"report_{job_id}")
    
    # Determine media type
    if filename.endswith(".pdf"):
        media_type = "application/pdf"
    else:
        media_type = "text/html"
    
    return FileResponse(
        path=filepath,
        filename=filename,
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


@router.get("/available-projects")
def get_available_projects(db: Session = Depends(get_db)):
    """
    Get list of projects available for report generation
    """
    projects = db.query(Project).filter(Project.is_active == True).all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "last_scan_at": p.last_scan_at.isoformat() if p.last_scan_at else None
        }
        for p in projects
    ]
