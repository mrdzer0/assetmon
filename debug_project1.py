from app.db import SessionLocal
from app.models import Project
import json

db = SessionLocal()
p = db.query(Project).filter(Project.id == 1).first()

print(f"Project ID: {p.id}")
print(f"Name: {p.name}")
print(f"Raw Config Type: {type(p.notification_config)}")
print(f"Raw Config: {p.notification_config}")

if isinstance(p.notification_config, str):
    try:
        parsed = json.loads(p.notification_config)
        print(f"Parsed Config Type: {type(parsed)}")
        print(f"Parsed Config: {parsed}")
    except Exception as e:
        print(f"JSON Parse Error: {e}")

# Check why tasks.py might fail
notif = p.notification_config
if isinstance(notif, str):
    try:
        notif = json.loads(notif)
    except:
        notif = {}
elif notif is None:
    notif = {}

print(f"Processed Config: {notif}")
print(f"Processed Type: {type(notif)}")

if isinstance(notif, dict):
    print(f"Discord: {notif.get('discord')}, Type: {type(notif.get('discord'))}")
    print(f"Slack: {notif.get('slack')}, Type: {type(notif.get('slack'))}")
    print(f"Telegram: {notif.get('telegram')}, Type: {type(notif.get('telegram'))}")
else:
    print("Processed config is NOT a dict!")
