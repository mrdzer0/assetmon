#!/usr/bin/env python3
"""
Database Migration Script
Updates the database schema and data to support new features.

Run this script after pulling new code:
    python migrate_db.py

This script will:
1. Create any missing tables
2. Add new ScannerConfig entries (scan_modes, etc.)
3. Update existing entries with new fields if needed
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from app.db import Base, engine, SessionLocal
from app.models import ScannerConfig, SnapshotType
from app.config import settings


def migrate():
    print("=" * 60)
    print("Asset Monitor - Database Migration Script")
    print("=" * 60)
    
    # Create session
    db = SessionLocal()
    
    try:
        # 1. Create all tables (safe - doesn't modify existing tables)
        print("\n[1/4] Creating missing tables...")
        Base.metadata.create_all(bind=engine)
        print("     ✓ Tables created/verified")
        
        # 2. Add missing ScannerConfig entries
        print("\n[2/4] Adding missing ScannerConfig entries...")
        added = []
        for key, data in ScannerConfig.DEFAULTS.items():
            existing = db.query(ScannerConfig).filter(ScannerConfig.key == key).first()
            if not existing:
                config = ScannerConfig(
                    key=key,
                    value=data["value"],
                    description=data["description"]
                )
                db.add(config)
                added.append(key)
                print(f"     + Added: {key}")
        
        if not added:
            print("     ✓ All ScannerConfig entries already exist")
        
        db.commit()
        
        # 3. Update port_config with screenshot_enabled if missing
        print("\n[3/4] Updating port_config with new fields...")
        port_config = db.query(ScannerConfig).filter(ScannerConfig.key == "port_config").first()
        if port_config:
            value = port_config.value or {}
            updated = False
            
            if "screenshot_enabled" not in value:
                value["screenshot_enabled"] = False
                updated = True
                print("     + Added screenshot_enabled to port_config")
            
            if updated:
                port_config.value = value
                port_config.updated_at = datetime.utcnow()
                db.commit()
            else:
                print("     ✓ port_config already up to date")
        
        # 4. Verify SnapshotType enum has PORTS
        print("\n[4/4] Verifying SnapshotType enum...")
        try:
            _ = SnapshotType.PORTS
            print("     ✓ SnapshotType.PORTS exists")
        except AttributeError:
            print("     ⚠ SnapshotType.PORTS missing - please update app/models.py")
        
        print("\n" + "=" * 60)
        print("Migration completed successfully!")
        print("=" * 60)
        
        # Show current config
        print("\n📋 Current ScannerConfig entries:")
        configs = db.query(ScannerConfig).all()
        for config in configs:
            print(f"   • {config.key}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        db.rollback()
        return False
        
    finally:
        db.close()


if __name__ == "__main__":
    success = migrate()
    sys.exit(0 if success else 1)
