"""
Settings API router
Manages scanner configuration and tool status
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any
from datetime import datetime
import shutil
import logging

from app.db import get_db
from app.models import ScannerConfig, User
from app.config import settings
from app.auth import get_current_user

router = APIRouter(prefix="/api/settings", tags=["settings"])
logger = logging.getLogger(__name__)


def get_scanner_config(db: Session, key: str) -> Dict:
    """Get a scanner config value, returning default if not set"""
    config = db.query(ScannerConfig).filter(ScannerConfig.key == key).first()
    if config:
        return config.value
    # Return default
    if key in ScannerConfig.DEFAULTS:
        return ScannerConfig.DEFAULTS[key]["value"]
    return {}


def set_scanner_config(db: Session, key: str, value: Dict, description: str = None) -> ScannerConfig:
    """Set a scanner config value"""
    config = db.query(ScannerConfig).filter(ScannerConfig.key == key).first()
    if config:
        config.value = value
        config.updated_at = datetime.utcnow()
        if description:
            config.description = description
    else:
        desc = description or ScannerConfig.DEFAULTS.get(key, {}).get("description", "")
        config = ScannerConfig(key=key, value=value, description=desc)
        db.add(config)
    db.commit()
    db.refresh(config)
    return config


def init_default_configs(db: Session):
    """Initialize default configs if not exist"""
    for key, data in ScannerConfig.DEFAULTS.items():
        existing = db.query(ScannerConfig).filter(ScannerConfig.key == key).first()
        if not existing:
            config = ScannerConfig(
                key=key,
                value=data["value"],
                description=data["description"]
            )
            db.add(config)
    db.commit()


@router.get("/scanners")
def get_all_scanner_configs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all scanner configurations"""
    # Ensure defaults exist
    init_default_configs(db)
    
    configs = db.query(ScannerConfig).all()
    result = {}
    for config in configs:
        result[config.key] = {
            "value": config.value,
            "description": config.description,
            "updated_at": config.updated_at.isoformat() if config.updated_at else None
        }
    return result


@router.put("/scanners/{key}")
def update_scanner_config(
    key: str,
    data: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a specific scanner configuration"""
    if key not in ScannerConfig.DEFAULTS:
        raise HTTPException(status_code=400, detail=f"Invalid config key: {key}")
    
    value = data.get("value", data)
    config = set_scanner_config(db, key, value)
    
    logger.info(f"Updated scanner config: {key}")
    
    return {
        "key": config.key,
        "value": config.value,
        "description": config.description,
        "updated_at": config.updated_at.isoformat()
    }


@router.put("/scanners")
def update_all_scanner_configs(
    data: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update multiple scanner configurations at once"""
    updated = []
    for key, config_data in data.items():
        if key in ScannerConfig.DEFAULTS:
            value = config_data.get("value", config_data) if isinstance(config_data, dict) else config_data
            config = set_scanner_config(db, key, value)
            updated.append(key)
    
    logger.info(f"Updated scanner configs: {updated}")
    
    return {"updated": updated, "count": len(updated)}


@router.get("/tools-status")
def get_tools_status(current_user: User = Depends(get_current_user)):
    """Check which tools are installed and available"""
    tools = {
        "subfinder": settings.subfinder_path,
        "assetfinder": settings.assetfinder_path,
        "amass": settings.amass_path,
        "dnsx": settings.dnsx_path,
        "httpx": settings.httpx_path,
        "waybackurls": settings.waybackurls_path,
        "gau": settings.gau_path,
        "katana": settings.katana_path,
        "nuclei": settings.nuclei_path,
        "naabu": settings.naabu_path,
    }
    
    result = {}
    for name, path in tools.items():
        found_path = shutil.which(path)
        result[name] = {
            "installed": found_path is not None,
            "path": found_path or path,
            "configured_path": path
        }
    
    return result


@router.post("/scanners/reset")
def reset_scanner_configs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Reset all scanner configs to defaults"""
    # Delete all existing configs
    db.query(ScannerConfig).delete()
    db.commit()
    
    # Re-init defaults
    init_default_configs(db)
    
    logger.info("Reset all scanner configs to defaults")
    
    return {"message": "All scanner configs reset to defaults"}
