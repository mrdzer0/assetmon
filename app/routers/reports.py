"""
Reports API endpoints
Generate PDF and HTML reports for projects
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse, HTMLResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import io
import logging

from app.db import get_db
from app.models import Project, ScanLog, Snapshot, SnapshotType, Event
from app.services.report_generator import ReportGenerator

router = APIRouter(prefix="/api/reports", tags=["reports"])
logger = logging.getLogger(__name__)


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


@router.post("/generate")
def generate_report(
    request: ReportRequest,
    db: Session = Depends(get_db)
):
    """
    Generate a report for selected projects
    
    Args:
        project_ids: List of project IDs to include
        format: Output format (pdf or html)
        sections: Which sections to include
    
    Returns:
        StreamingResponse with the report file
    """
    # Validate projects exist
    projects = db.query(Project).filter(Project.id.in_(request.project_ids)).all()
    if not projects:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No projects found with the given IDs"
        )
    
    if len(projects) != len(request.project_ids):
        found_ids = {p.id for p in projects}
        missing_ids = set(request.project_ids) - found_ids
        logger.warning(f"Some projects not found: {missing_ids}")
    
    # Generate report
    generator = ReportGenerator(db)
    
    try:
        if request.format.lower() == "html":
            html_content = generator.generate_html_report(
                projects=projects,
                sections=request.sections.model_dump(),
                company=request.company.model_dump()
            )
            return HTMLResponse(
                content=html_content,
                headers={
                    "Content-Disposition": f"attachment; filename=report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                }
            )
        else:
            # PDF format
            pdf_bytes = generator.generate_pdf_report(
                projects=projects,
                sections=request.sections.model_dump(),
                company=request.company.model_dump()
            )
            return StreamingResponse(
                io.BytesIO(pdf_bytes),
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename=report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                }
            )
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {str(e)}"
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
