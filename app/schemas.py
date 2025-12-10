"""
Pydantic schemas for request/response validation
"""

from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from app.models import SeverityLevel, EventType, SnapshotType


# Project Schemas
class DomainBase(BaseModel):
    name: str = Field(..., description="Domain name (e.g., example.com)")


class DomainCreate(DomainBase):
    pass


class Domain(DomainBase):
    id: int
    project_id: int
    created_at: datetime
    is_active: bool

    class Config:
        from_attributes = True


class ProjectBase(BaseModel):
    name: str = Field(..., description="Project name")
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    notification_config: Optional[Dict[str, Any]] = None


class ProjectCreate(ProjectBase):
    domains: List[str] = Field(default_factory=list, description="List of root domains")


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    domains: Optional[List[str]] = None
    config: Optional[Dict[str, Any]] = None
    notification_config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class Project(ProjectBase):
    id: int
    created_at: datetime
    updated_at: datetime
    last_scan_at: Optional[datetime] = None
    last_weekly_scan_at: Optional[datetime] = None
    is_active: bool
    domains: List[Domain] = []

    class Config:
        from_attributes = True


# Snapshot Schemas
class SnapshotBase(BaseModel):
    project_id: int
    type: SnapshotType
    data: Dict[str, Any]
    scan_metadata: Optional[Dict[str, Any]] = None


class SnapshotCreate(SnapshotBase):
    pass


class Snapshot(SnapshotBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# Event Schemas
class EventBase(BaseModel):
    project_id: int
    type: EventType
    severity: SeverityLevel
    summary: str
    details: Optional[Dict[str, Any]] = None
    related_entities: Optional[Dict[str, Any]] = None


class EventCreate(EventBase):
    pass


class EventUpdate(BaseModel):
    seen: Optional[bool] = None
    acknowledged: Optional[bool] = None
    acknowledged_by: Optional[str] = None


class Event(EventBase):
    id: int
    created_at: datetime
    seen: bool
    acknowledged: bool
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    notified: bool
    notified_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# Scan Request/Response Schemas
class ScanRequest(BaseModel):
    project_id: int
    mode: str = Field("normal", description="Scan mode: 'normal', 'weekly', or 'custom'")
    modules: Optional[List[str]] = Field(None, description="Custom modules to run: normal, endpoints, shodan, nuclei, ports")

    @validator("mode")
    def validate_mode(cls, v):
        if v not in ["normal", "weekly", "custom"]:
            raise ValueError("Mode must be 'normal', 'weekly', or 'custom'")
        return v


class ScanResponse(BaseModel):
    scan_id: Optional[int] = None
    project_id: int
    mode: str
    status: str
    events_generated: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    errors: List[str] = []


# Scanner Result Schemas
class SubdomainResult(BaseModel):
    """Result from subdomain discovery"""
    subdomains: List[str]
    source: str  # "subfinder", "assetfinder", etc.
    count: int


class DNSRecord(BaseModel):
    """DNS resolution result"""
    subdomain: str
    a_records: List[str] = []
    cname_records: List[str] = []
    has_resolution: bool = True
    error: Optional[str] = None


class HTTPRecord(BaseModel):
    """HTTP probe result"""
    url: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    content_length: Optional[int] = None
    technologies: List[str] = []
    ip: Optional[str] = None
    cname: Optional[str] = None
    cdn: Optional[str] = None
    error: Optional[str] = None


class ShodanHostInfo(BaseModel):
    """Shodan host information"""
    ip: str
    ports: List[int] = []
    hostnames: List[str] = []
    vulns: List[str] = []
    services: List[Dict[str, Any]] = []


class TakeoverFinding(BaseModel):
    """Subdomain takeover finding"""
    subdomain: str
    cname: str
    reason: str  # "cname_dead_service", "nxdomain_with_cname", etc.
    service: Optional[str] = None  # "vercel", "netlify", etc.
    severity: SeverityLevel = SeverityLevel.HIGH
    verified: bool = False


class EndpointResult(BaseModel):
    """Endpoint discovery result"""
    urls: List[str]
    js_files: List[str]
    source: str  # "waybackurls", "gau", "katana"


# Dashboard Stats
class ProjectStats(BaseModel):
    """Statistics for project dashboard"""
    project_id: int
    project_name: str
    total_domains: int
    total_subdomains: int
    total_endpoints: int
    last_scan_at: Optional[datetime] = None
    recent_events_count: int
    high_severity_events: int


class DashboardStats(BaseModel):
    """Overall dashboard statistics"""
    total_projects: int
    active_projects: int
    total_events_today: int
    high_severity_events_today: int
    last_scan: Optional[datetime] = None
    projects: List[ProjectStats] = []
