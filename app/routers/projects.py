"""
Projects API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.db import get_db
from app.models import Project, Domain, Snapshot, SnapshotType
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

    # Update domains if provided
    if project_data.domains is not None:
        # Get current domains
        current_domains = {d.name for d in project.domains}
        new_domains = set(project_data.domains)

        # Find domains to remove (in current but not in new)
        domains_to_remove = current_domains - new_domains

        # Find domains to add (in new but not in current)
        domains_to_add = new_domains - current_domains

        # Remove domains
        if domains_to_remove:
            db.query(Domain).filter(
                Domain.project_id == project_id,
                Domain.name.in_(domains_to_remove)
            ).delete(synchronize_session=False)

        # Add new domains
        for domain_name in domains_to_add:
            domain = Domain(project_id=project_id, name=domain_name)
            db.add(domain)

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


@router.get("/{project_id}/graph")
def get_project_graph(project_id: int, db: Session = Depends(get_db)):
    """Get graph data for the project (nodes and edges) with rich metadata"""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found"
        )

    # Fetch latest snapshots
    snapshots = {}
    for type_ in [SnapshotType.SUBDOMAINS, SnapshotType.DNS, SnapshotType.HTTP, SnapshotType.SHODAN]:
        snapshot = db.query(Snapshot).filter(
            Snapshot.project_id == project_id,
            Snapshot.type == type_
        ).order_by(Snapshot.created_at.desc()).first()
        if snapshot:
            snapshots[type_] = snapshot.data

    nodes = []
    edges = []
    node_ids = set()
    
    # Statistics counters
    stats = {
        "domains": 0,
        "subdomains": 0,
        "ips": 0,
        "ports": 0,
        "vulns": 0,
        "cnames": 0
    }

    def add_node(id_, label, group, title=None, metadata=None):
        if id_ not in node_ids:
            node = {
                "id": id_,
                "label": label,
                "group": group,
                "title": title or label,
                "metadata": metadata or {}
            }
            nodes.append(node)
            node_ids.add(id_)
            # Update stats
            if group in stats:
                stats[group] += 1
            elif group == "ip":
                stats["ips"] += 1
            elif group == "subdomain":
                stats["subdomains"] += 1
            elif group == "domain":
                stats["domains"] += 1
            elif group == "port":
                stats["ports"] += 1
            elif group == "vuln":
                stats["vulns"] += 1
            elif group == "cname":
                stats["cnames"] += 1

    def add_edge(from_, to_, label=None):
        edge = {"from": from_, "to": to_}
        if label:
            edge["label"] = label
        edges.append(edge)

    # 1. Root Domains
    for domain in project.domains:
        add_node(
            domain.name, 
            domain.name, 
            "domain",
            f"Root Domain: {domain.name}",
            {"type": "domain", "created_at": domain.created_at.isoformat() if domain.created_at else None}
        )

    # 2. Subdomains
    subdomains_data = snapshots.get(SnapshotType.SUBDOMAINS, {}).get("subdomains", [])
    http_data = snapshots.get(SnapshotType.HTTP, {}).get("http_records", {})
    
    for sub in subdomains_data:
        # Determine parent domain
        parent = next((d.name for d in project.domains if sub.endswith(d.name)), None)
        
        # HTTP info
        http_info = http_data.get(f"https://{sub}") or http_data.get(f"http://{sub}")
        title = f"Subdomain: {sub}"
        metadata = {"type": "subdomain", "parent": parent}
        
        if http_info:
            status_code = http_info.get('status_code')
            title_text = http_info.get('title', '')
            technologies = http_info.get('technologies', [])
            cdn = http_info.get('cdn', '')
            
            title += f"\nStatus: {status_code}"
            if title_text:
                title += f"\nTitle: {title_text}"
            if technologies:
                title += f"\nTech: {', '.join(technologies[:5])}"
            if cdn:
                title += f"\nCDN: {cdn}"
            
            metadata.update({
                "status_code": status_code,
                "title": title_text,
                "technologies": technologies,
                "cdn": cdn,
                "url": f"https://{sub}"
            })
        
        add_node(sub, sub, "subdomain", title, metadata)
        if parent:
            add_edge(parent, sub)

    # 3. DNS (IPs)
    dns_records = snapshots.get(SnapshotType.DNS, {}).get("dns_records", {})
    existing_ips = set()
    ip_to_subdomains = {}  # Track which subdomains resolve to which IPs
    
    for sub, record in dns_records.items():
        if sub not in node_ids:
            continue
            
        for ip in record.get("a", []):
            if ip not in ip_to_subdomains:
                ip_to_subdomains[ip] = []
            ip_to_subdomains[ip].append(sub)
            
            add_node(
                ip, ip, "ip",
                f"IP: {ip}\nSubdomains: {len(ip_to_subdomains[ip])}",
                {"type": "ip", "subdomains": ip_to_subdomains[ip]}
            )
            add_edge(sub, ip)
            existing_ips.add(ip)
            
        for cname in record.get("cname", []):
            add_node(
                cname, cname, "cname",
                f"CNAME: {cname}",
                {"type": "cname", "source": sub}
            )
            add_edge(sub, cname)

    # 4. Shodan (Ports/Vulns)
    shodan_results = snapshots.get(SnapshotType.SHODAN, {}).get("shodan_results", {})
    
    for ip, data in shodan_results.items():
        if ip in existing_ips:
            # Update IP node metadata with Shodan info
            for node in nodes:
                if node["id"] == ip:
                    node["metadata"]["ports"] = data.get("ports", [])
                    node["metadata"]["vulns"] = data.get("vulns", [])
                    node["metadata"]["org"] = data.get("org", "")
                    node["metadata"]["isp"] = data.get("isp", "")
                    node["title"] += f"\nPorts: {len(data.get('ports', []))}"
                    node["title"] += f"\nVulns: {len(data.get('vulns', []))}"
                    break
            
            # Add ports
            for port in data.get("ports", []):
                port_id = f"{ip}:{port}"
                add_node(
                    port_id, str(port), "port",
                    f"Port: {port}\nIP: {ip}",
                    {"type": "port", "port": port, "ip": ip}
                )
                add_edge(ip, port_id)
            
            # Add Vulns
            for vuln in data.get("vulns", []):
                vuln_id = f"{ip}:{vuln}"
                add_node(
                    vuln_id, vuln, "vuln",
                    f"Vulnerability: {vuln}\nIP: {ip}",
                    {"type": "vuln", "cve": vuln, "ip": ip}
                )
                add_edge(ip, vuln_id)

    return {
        "nodes": nodes, 
        "edges": edges,
        "stats": stats,
        "total_nodes": len(nodes),
        "total_edges": len(edges)
    }
