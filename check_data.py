from app.db import SessionLocal
from app.models import Snapshot, SnapshotType, Event
from sqlalchemy import desc
from datetime import datetime, timedelta

def check_dashboard_data():
    db = SessionLocal()
    project_id = 1
    
    print(f"--- Checking Dashboard Data for Project {project_id} ---")
    
    # 1. Check Snapshots (String vs Enum)
    latest_snapshots = {}
    snap_types = ["subdomains", "dns", "http"]
    
    for snap_type in snap_types:
        snapshot = db.query(Snapshot).filter(
            Snapshot.project_id == project_id,
            Snapshot.type == snap_type
        ).order_by(Snapshot.created_at.desc()).first()
        
        if snapshot:
            latest_snapshots[snap_type] = snapshot
            print(f"✅ Found snapshot for '{snap_type}' (String query)")
        else:
            print(f"❌ No snapshot for '{snap_type}' (String query)")

    # 2. Check counts logic
    status_counts = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "Other": 0}
    if "http" in latest_snapshots and latest_snapshots["http"].data:
        http_records = latest_snapshots["http"].data.get("http_records", {})
        print(f"HTTP Records Found: {len(http_records)}")
        for record in http_records.values():
            code = record.get("status_code")
            if code:
                if 200 <= code < 300: status_counts["2xx"] += 1
                elif 300 <= code < 400: status_counts["3xx"] += 1
                elif 400 <= code < 500: status_counts["4xx"] += 1
                elif 500 <= code < 600: status_counts["5xx"] += 1
                else: status_counts["Other"] += 1
    else:
        print("HTTP snapshot missing or empty data.")
        
    print(f"Calculated Status Counts: {status_counts}")

    db.close()

if __name__ == "__main__":
    check_dashboard_data()
