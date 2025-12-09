"""
SQLAlchemy database models
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, JSON, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from app.db import Base


class SeverityLevel(str, enum.Enum):
    """Severity levels for events"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, enum.Enum):
    """Types of events/changes detected"""
    SUBDOMAIN_NEW = "subdomain_new"
    SUBDOMAIN_REMOVED = "subdomain_removed"
    DNS_CHANGED = "dns_changed"
    HTTP_STATUS_CHANGED = "http_status_changed"
    HTTP_TITLE_CHANGED = "http_title_changed"
    HTTP_CONTENT_CHANGED = "http_content_changed"
    PORT_NEW = "port_new"
    PORT_REMOVED = "port_removed"
    ENDPOINT_NEW = "endpoint_new"
    JS_FILE_NEW = "js_file_new"
    TAKEOVER_SUSPECTED = "takeover_suspected"
    VULNERABILITY_FOUND = "vulnerability_found"


class SnapshotType(str, enum.Enum):
    """Types of snapshots"""
    SUBDOMAINS = "subdomains"
    DNS = "dns"
    HTTP = "http"
    SHODAN = "shodan"
    ENDPOINTS = "endpoints"


class Project(Base):
    """
    Project represents a monitoring target (e.g., "my-company-main")
    """
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Configuration stored as JSON
    # Example: {"enabled_tools": {"subdomains": {"enabled": true, "sources": ["subfinder", "assetfinder"]}, ...}}
    config = Column(JSON, nullable=True)

    # Notification settings stored as JSON
    # Example: {"slack": {"enabled": true, "webhook_url": "..."}, "min_severity": "medium"}
    notification_config = Column(JSON, nullable=True)

    # Last scan timestamps
    last_scan_at = Column(DateTime, nullable=True)
    last_weekly_scan_at = Column(DateTime, nullable=True)

    # Status
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    domains = relationship("Domain", back_populates="project", cascade="all, delete-orphan")
    snapshots = relationship("Snapshot", back_populates="project", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="project", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Project(id={self.id}, name='{self.name}')>"


class Domain(Base):
    """
    Domain represents a root domain to monitor within a project
    """
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    project = relationship("Project", back_populates="domains")

    def __repr__(self):
        return f"<Domain(id={self.id}, name='{self.name}', project_id={self.project_id})>"


class Snapshot(Base):
    """
    Snapshot stores the state of assets at a point in time
    """
    __tablename__ = "snapshots"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    type = Column(SQLEnum(SnapshotType), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Data stored as JSON
    # Structure depends on type:
    # - subdomains: {"subdomains": ["api.example.com", "www.example.com"]}
    # - dns: {"api.example.com": {"a": ["1.2.3.4"], "cname": ["alias.example.com"]}, ...}
    # - http: {"api.example.com": {"status": 200, "title": "...", "content_length": 1234, ...}, ...}
    # - shodan: {"1.2.3.4": {"ports": [80, 443], "vulns": [...], ...}, ...}
    # - endpoints: {"urls": ["https://example.com/api/v1", ...], "js_files": ["https://example.com/app.js", ...]}
    data = Column(JSON, nullable=False)

    # Metadata about the scan
    # Example: {"scan_mode": "normal", "duration_seconds": 120, "tool_versions": {...}}
    scan_metadata = Column(JSON, nullable=True)

    # Relationships
    project = relationship("Project", back_populates="snapshots")

    def __repr__(self):
        return f"<Snapshot(id={self.id}, type='{self.type}', project_id={self.project_id})>"


class Event(Base):
    """
    Event represents a detected change or alert
    """
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    type = Column(SQLEnum(EventType), nullable=False, index=True)
    severity = Column(SQLEnum(SeverityLevel), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Summary for display
    summary = Column(Text, nullable=False)

    # Detailed information stored as JSON
    # Example: {"old_value": {...}, "new_value": {...}, "diff": {...}}
    details = Column(JSON, nullable=True)

    # Related entities
    # Example: {"subdomain": "api.example.com", "ip": "1.2.3.4"}
    related_entities = Column(JSON, nullable=True)

    # Status flags
    seen = Column(Boolean, default=False, nullable=False)
    acknowledged = Column(Boolean, default=False, nullable=False)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(255), nullable=True)

    # Notification status
    notified = Column(Boolean, default=False, nullable=False)
    notified_at = Column(DateTime, nullable=True)

    # Relationships
    project = relationship("Project", back_populates="events")

    def __repr__(self):
        return f"<Event(id={self.id}, type='{self.type}', severity='{self.severity}', project_id={self.project_id})>"


class ScanLog(Base):
    """
    ScanLog tracks scan executions for debugging and monitoring
    """
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)

    scan_mode = Column(String(50), nullable=False)  # "normal" or "weekly"
    status = Column(String(50), nullable=False, default="running")  # "running", "completed", "failed"

    # Stats and results
    events_generated = Column(Integer, default=0)
    errors = Column(JSON, nullable=True)  # List of errors if any

    # Tool execution details
    tools_executed = Column(JSON, nullable=True)  # {"subfinder": {"duration": 12.5, "results_count": 50}, ...}

    # Relationships
    project = relationship("Project")

    def __repr__(self):
        return f"<ScanLog(id={self.id}, project_id={self.project_id}, mode='{self.scan_mode}', status='{self.status}')>"


class User(Base):
    """
    User model for authentication
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)

    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', is_active={self.is_active})>"
