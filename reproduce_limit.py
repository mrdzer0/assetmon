
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

# Generate 1000 URLs
urls = [f"http://example.com/api/{i}" for i in range(1000)]

snapshot.data = {
    "urls": urls,
    "enriched_urls": [], # Use plain urls fallback
    "js_files": []
}

# Setup DB query mock
db.query.return_value.filter.return_value.order_by.return_value.first.return_value = snapshot

print("Testing with 1000 endpoints...")
result = get_project_endpoints(
    project_id=1, 
    db=db, 
    current_user=MagicMock(), 
    per_page=500 # Request 500 per page
)
print(f"Total reported: {result['total']}")
print(f"Items returned: {len(result['endpoints'])}")
