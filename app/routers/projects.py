"""
Projects API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.db import get_db
from app.models import Project, Domain
from app.schemas import (
    Project as ProjectSchema,
    ProjectCreate,
    ProjectUpdate,
    Domain as DomainSchema
)

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("/", response_model=List[ProjectSchema])
def list_projects(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    db: Session = Depends(get_db)
):
    """List all projects"""
    query = db.query(Project)

    if active_only:
        query = query.filter(Project.is_active == True)

    projects = query.offset(skip).limit(limit).all()
    return projects


@router.get("/{project_id}", response_model=ProjectSchema)
def get_project(project_id: int, db: Session = Depends(get_db)):
    """Get project by ID"""
    project = db.query(Project).filter(Project.id == project_id).first()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )

    return project


@router.post("/", response_model=ProjectSchema, status_code=status.HTTP_201_CREATED)
def create_project(project_data: ProjectCreate, db: Session = Depends(get_db)):
    """Create a new project"""
    # Check if project name already exists
    existing = db.query(Project).filter(Project.name == project_data.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Project with name '{project_data.name}' already exists"
        )

    # Create project
    project = Project(
        name=project_data.name,
        description=project_data.description,
        config=project_data.config,
        notification_config=project_data.notification_config
    )

    db.add(project)
    db.flush()  # Get project ID

    # Add domains
    for domain_name in project_data.domains:
        domain = Domain(project_id=project.id, name=domain_name)
        db.add(domain)

    db.commit()
    db.refresh(project)

    return project


@router.put("/{project_id}", response_model=ProjectSchema)
def update_project(
    project_id: int,
    project_data: ProjectUpdate,
    db: Session = Depends(get_db)
):
    """Update a project"""
    project = db.query(Project).filter(Project.id == project_id).first()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )

    # Update fields
    if project_data.name is not None:
        project.name = project_data.name
    if project_data.description is not None:
        project.description = project_data.description
    if project_data.config is not None:
        project.config = project_data.config
    if project_data.notification_config is not None:
        project.notification_config = project_data.notification_config
    if project_data.is_active is not None:
        project.is_active = project_data.is_active

    db.commit()
    db.refresh(project)

    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: int, db: Session = Depends(get_db)):
    """Delete a project"""
    project = db.query(Project).filter(Project.id == project_id).first()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )

    db.delete(project)
    db.commit()

    return None


@router.post("/{project_id}/domains", response_model=DomainSchema)
def add_domain(
    project_id: int,
    domain_name: str,
    db: Session = Depends(get_db)
):
    """Add a domain to a project"""
    project = db.query(Project).filter(Project.id == project_id).first()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )

    # Check if domain already exists
    existing = db.query(Domain).filter(
        Domain.project_id == project_id,
        Domain.name == domain_name
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Domain '{domain_name}' already exists in this project"
        )

    domain = Domain(project_id=project_id, name=domain_name)
    db.add(domain)
    db.commit()
    db.refresh(domain)

    return domain


@router.delete("/{project_id}/domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_domain(
    project_id: int,
    domain_id: int,
    db: Session = Depends(get_db)
):
    """Remove a domain from a project"""
    domain = db.query(Domain).filter(
        Domain.id == domain_id,
        Domain.project_id == project_id
    ).first()

    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain {domain_id} not found in project {project_id}"
        )

    db.delete(domain)
    db.commit()

    return None
