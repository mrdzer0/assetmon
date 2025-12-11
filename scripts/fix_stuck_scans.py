import logging
import sys
import os

# Add parent directory to path to allow importing app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db import SessionLocal
from app.models import ScanLog
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fix_stuck_scans():
    db = SessionLocal()
    try:
        # Find all scans with status 'queued'
        stuck_scans = db.query(ScanLog).filter(ScanLog.status == "queued").all()
        
        if not stuck_scans:
            logger.info("No stuck 'queued' scans found.")
            return

        logger.info(f"Found {len(stuck_scans)} stuck scans. Updating to 'failed'...")
        
        for scan in stuck_scans:
            scan.status = "failed"
            # Initialize errors dict if it's None, or append to it
            current_errors = scan.errors or {}
            if isinstance(current_errors, dict):
                current_errors["manual_update"] = "Marked as failed by cleanup script"
            elif isinstance(current_errors, list):
                current_errors.append("Marked as failed by cleanup script")
            
            scan.errors = current_errors
            scan.completed_at = datetime.utcnow()
            logger.info(f"Updated Scan ID {scan.id} (Project {scan.project_id})")

        db.commit()
        logger.info("Successfully updated all stuck scans.")
        
    except Exception as e:
        logger.error(f"Error updating scans: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    fix_stuck_scans()
