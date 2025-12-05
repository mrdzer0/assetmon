
from app.routers.dashboard import get_project_endpoints
from app.models import Project, Snapshot
from unittest.mock import MagicMock
from datetime import datetime

# Mock DB and objects
db = MagicMock()
snapshot = MagicMock()
snapshot.project_id = 1
snapshot.type = "endpoints"
snapshot.created_at = datetime.now()
snapshot.data = {
    "urls": ["http://example.com/api"],
    "enriched_urls": [
        {
            "url": "http://example.com/api",
            "title": None,  # Simulate NULL title
            "status_code": 200
        }
    ],
    "js_files": []
}

# Setup DB query mock
db.query.return_value.filter.return_value.order_by.return_value.first.return_value = snapshot

print("Testing search with NULL title...")
try:
    result = get_project_endpoints(
        project_id=1, 
        db=db, 
        current_user=MagicMock(), 
        search="login"
    )
    print("Success!")
except Exception as e:
    print(f"Crashed as expected: {e}")
