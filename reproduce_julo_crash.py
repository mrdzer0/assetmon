
from app.routers.dashboard import get_project_endpoints
from app.models import Project, Snapshot
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import MagicMock
import traceback

# Connect to the local assetmon.db
engine = create_engine('sqlite:///assetmon.db')
Session = sessionmaker(bind=engine)
session = Session()

print("Testing Project 1 (JULO)...")
try:
    # We need to mock current_user
    current_user = MagicMock()
    
    # Simulate the request params: page=1&per_page=100&search=&exclude=&category=&status=
    result = get_project_endpoints(
        project_id=1, 
        db=session, 
        current_user=current_user,
        per_page=100, 
        page=1,
        search="",
        exclude="",
        category="",
        status=""
    )
    
    print(f"Total: {result['total']}")
    print("Success!")
    
except Exception as e:
    print(f"CRASHED: {e}")
    traceback.print_exc()
