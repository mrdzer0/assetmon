import logging
import traceback
from app.db import SessionLocal
from app.models import Project
from app.services.orchestrator import ScanOrchestrator
from app.tasks import create_notification_manager

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_debug_scan(project_id):
    print(f"--- Debugging Project {project_id} ---")
    db = SessionLocal()
    try:
        # 1. Test Notification Manager Creation
        print("Creating Notification Manager...")
        try:
            notif_mgr = create_notification_manager(db, project_id)
            print("Notification Manager created successfully.")
        except Exception as e:
            print(f"FAILED to create Notification Manager: {e}")
            traceback.print_exc()
            return

        # 2. Test Orchestrator Run
        print("Initializing Orchestrator...")
        orchestrator = ScanOrchestrator(db, notif_mgr)
        
        print("Running Scan (dry run if possible, but we will let it fail)...")
        # We might not want to actually run a full scan if it takes forever, 
        # but the error seems to happen early (queued -> failed quickly).
        # Let's try to run it.
        try:
            orchestrator.run_scan(project_id, mode="normal")
            print("Scan completed successfully (unexpectedly).")
        except Exception as e:
            print(f"Scan FAILED as expected: {e}")
            print("--- FULL TRACEBACK ---")
            traceback.print_exc()
            
    finally:
        db.close()

if __name__ == "__main__":
    run_debug_scan(1)
