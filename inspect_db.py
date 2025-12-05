
from app.models import Project, Snapshot
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import json

# Connect to the local assetmon.db
engine = create_engine('sqlite:///assetmon.db')
Session = sessionmaker(bind=engine)
session = Session()


print("Project 2 (Tesla) Snapshots history:")
snapshots = session.query(Snapshot).filter(
    Snapshot.project_id == 2,
    Snapshot.type == "endpoints"
).order_by(Snapshot.created_at.desc()).limit(5).all()

for s in snapshots:
    d = s.data
    urls = len(d.get("urls", []))
    enriched = len(d.get("enriched_urls", []))
    print(f"ID: {s.id}, Created: {s.created_at}, URLs: {urls}, Enriched: {enriched}")

