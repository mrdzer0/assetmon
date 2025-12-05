"""
Events and Snapshots API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.db import get_db
from app.models import Event, Snapshot, SeverityLevel, EventType, SnapshotType
from app.schemas import Event as EventSchema, EventUpdate, Snapshot as SnapshotSchema

router = APIRouter(prefix="/api", tags=["events"])


@router.get("/events", response_model=List[EventSchema])
def list_events(
    project_id: Optional[int] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    seen: Optional[bool] = None,
    acknowledged: Optional[bool] = None,
    days: Optional[int] = Query(7, description="Number of days to look back"),
    exclude: Optional[str] = Query(None, description="Comma-separated patterns to exclude"),
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    List events with filtering options

    Args:
        project_id: Filter by project
        severity: Filter by severity (info, low, medium, high, critical)
        event_type: Filter by event type
        seen: Filter by seen status
        acknowledged: Filter by acknowledged status
        days: Number of days to look back (default: 7)
        exclude: Comma-separated patterns to exclude from summary
        skip: Pagination offset
        limit: Pagination limit
    """
    query = db.query(Event)

    # Exclude patterns
    if exclude:
        patterns = [p.strip() for p in exclude.split(",") if p.strip()]
        for pattern in patterns:
            # Filter out events where summary contains the pattern (case-insensitive)
            query = query.filter(~Event.summary.ilike(f"%{pattern}%"))

    # Filters
    if project_id:
        query = query.filter(Event.project_id == project_id)

    if severity:
        try:
            severity_enum = SeverityLevel(severity.lower())
            query = query.filter(Event.severity == severity_enum)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {severity}"
            )

    if event_type:
        try:
            type_enum = EventType(event_type.lower())
            query = query.filter(Event.type == type_enum)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid event type: {event_type}"
            )

    if seen is not None:
        query = query.filter(Event.seen == seen)

    if acknowledged is not None:
        query = query.filter(Event.acknowledged == acknowledged)

    # Date range
    if days:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(Event.created_at >= cutoff_date)

    # Order and paginate
    events = query.order_by(Event.created_at.desc()).offset(skip).limit(limit).all()

    return events


@router.get("/events/{event_id}", response_model=EventSchema)
def get_event(event_id: int, db: Session = Depends(get_db)):
    """Get specific event by ID"""
    event = db.query(Event).filter(Event.id == event_id).first()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event {event_id} not found"
        )

    return event


@router.patch("/events/{event_id}", response_model=EventSchema)
def update_event(
    event_id: int,
    event_update: EventUpdate,
    db: Session = Depends(get_db)
):
    """Update event (mark as seen/acknowledged)"""
    event = db.query(Event).filter(Event.id == event_id).first()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event {event_id} not found"
        )

    # Update fields
    if event_update.seen is not None:
        event.seen = event_update.seen

    if event_update.acknowledged is not None:
        event.acknowledged = event_update.acknowledged
        if event_update.acknowledged:
            event.acknowledged_at = datetime.utcnow()
            event.acknowledged_by = event_update.acknowledged_by or "user"

    db.commit()
    db.refresh(event)

    return event


@router.post("/events/bulk-update")
def bulk_update_events(
    event_ids: List[int],
    seen: Optional[bool] = None,
    acknowledged: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Bulk update multiple events"""
    events = db.query(Event).filter(Event.id.in_(event_ids)).all()

    if not events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No events found with provided IDs"
        )

    for event in events:
        if seen is not None:
            event.seen = seen
        if acknowledged is not None:
            event.acknowledged = acknowledged
            if acknowledged:
                event.acknowledged_at = datetime.utcnow()
                event.acknowledged_by = "user"

    db.commit()

    return {
        "success": True,
        "updated_count": len(events),
        "message": f"Updated {len(events)} events"
    }


@router.get("/events/stats")
def get_events_stats(
    project_id: Optional[int] = None,
    days: int = 7,
    db: Session = Depends(get_db)
):
    """Get events statistics"""
    query = db.query(Event)

    if project_id:
        query = query.filter(Event.project_id == project_id)

    cutoff_date = datetime.utcnow() - timedelta(days=days)
    query = query.filter(Event.created_at >= cutoff_date)

    events = query.all()

    # Count by severity
    severity_counts = {}
    for severity in SeverityLevel:
        count = sum(1 for e in events if e.severity == severity)
        severity_counts[severity.value] = count

    # Count by type
    type_counts = {}
    for event_type in EventType:
        count = sum(1 for e in events if e.type == event_type)
        if count > 0:
            type_counts[event_type.value] = count

    return {
        "total_events": len(events),
        "by_severity": severity_counts,
        "by_type": type_counts,
        "unseen": sum(1 for e in events if not e.seen),
        "unacknowledged": sum(1 for e in events if not e.acknowledged)
    }


# Snapshots endpoints

@router.get("/snapshots", response_model=List[SnapshotSchema])
def list_snapshots(
    project_id: Optional[int] = None,
    snapshot_type: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """List snapshots"""
    query = db.query(Snapshot)

    if project_id:
        query = query.filter(Snapshot.project_id == project_id)

    if snapshot_type:
        try:
            type_enum = SnapshotType(snapshot_type.lower())
            query = query.filter(Snapshot.type == type_enum)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid snapshot type: {snapshot_type}"
            )

    snapshots = query.order_by(Snapshot.created_at.desc()).limit(limit).all()

    return snapshots


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotSchema)
def get_snapshot(snapshot_id: int, db: Session = Depends(get_db)):
    """Get specific snapshot"""
    snapshot = db.query(Snapshot).filter(Snapshot.id == snapshot_id).first()

    if not snapshot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Snapshot {snapshot_id} not found"
        )

    return snapshot


@router.get("/snapshots/latest/{project_id}")
def get_latest_snapshots(project_id: int, db: Session = Depends(get_db)):
    """Get latest snapshot of each type for a project"""
    latest_snapshots = {}

    for snap_type in SnapshotType:
        snapshot = db.query(Snapshot).filter(
            Snapshot.project_id == project_id,
            Snapshot.type == snap_type
        ).order_by(Snapshot.created_at.desc()).first()

        if snapshot:
            latest_snapshots[snap_type.value] = {
                "id": snapshot.id,
                "created_at": snapshot.created_at,
                "metadata": snapshot.scan_metadata
            }

    return latest_snapshots
