
from app.routers.dashboard import get_project_endpoints
from app.models import Project, Snapshot
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import MagicMock

# Connect to the local assetmon.db
engine = create_engine('sqlite:///assetmon.db')
Session = sessionmaker(bind=engine)
session = Session()

print("Testing Project 2 (Tesla)...")
try:
    # We need to mock current_user
    current_user = MagicMock()
    
    result = get_project_endpoints(
        project_id=2, 
        db=session, 
        current_user=current_user,
        per_page=500, 
        page=1
    )
    
    print(f"Total: {result['total']}")
    print(f"Endpoints count in page: {len(result['endpoints'])}")
    
except Exception as e:
    print(f"Error: {e}")
