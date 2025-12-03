# Web Platform Guide

Complete guide untuk Asset Monitor Web Platform yang sudah fully implemented.

## ✅ Features Implemented

### 1. **Web UI (Dashboard)**
- Modern responsive design dengan sidebar navigation
- Real-time dashboard dengan statistics cards
- Project management interface
- Events viewer dengan filtering
- Scan history tracking

### 2. **Background Job System**
- APScheduler untuk scheduled scans
- Cron-based scheduling
- Automatic job setup on startup
- Job management API

### 3. **Notification System**
- **Slack**: Webhook integration dengan formatted blocks
- **Discord**: Webhook dengan rich embeds
- **Telegram**: Bot integration dengan markdown formatting
- Configurable per-project
- Severity-based filtering

### 4. **Scan Orchestrator**
- Coordinates all scanning services
- Diff logic untuk detect changes
- Event generation dan storage
- Notification dispatch
- Error handling dan retry logic

### 5. **REST API**
- Complete CRUD untuk projects
- Scan triggering dan scheduling
- Event management
- Snapshot retrieval
- Health checks

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Install CLI tools
./setup_tools.sh

# Configure API keys
./configure_apis.sh

# Install Python packages
pip install -r requirements.txt
```

### 2. Configure Environment

Edit `.env` file:

```bash
# Database
DATABASE_URL=sqlite:///./assetmon.db

# Shodan
SHODAN_API_KEY=your_shodan_api_key

# Notifications (optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

### 3. Initialize Database

```bash
python -c "from app.db import init_db; init_db()"
```

### 4. Run Web Server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Access Dashboard

Open browser: http://localhost:8000

## 📁 Project Structure

```
assetmon/
├── app/
│   ├── main.py                 # FastAPI application
│   ├── config.py               # Settings management
│   ├── db.py                   # Database setup
│   ├── models.py               # SQLAlchemy models
│   ├── schemas.py              # Pydantic schemas
│   ├── jobs.py                 # Background job scheduler
│   ├── routers/
│   │   ├── dashboard.py        # UI routes
│   │   ├── projects.py         # Projects API
│   │   ├── scans.py            # Scans API
│   │   └── events.py           # Events API
│   ├── services/
│   │   ├── orchestrator.py     # Scan orchestration
│   │   ├── scanner/            # All scanning services
│   │   │   ├── subdomains.py
│   │   │   ├── dns_monitor.py
│   │   │   ├── http_monitor.py
│   │   │   ├── shodan_monitor.py
│   │   │   └── endpoints.py
│   │   ├── diff/               # Change detection
│   │   │   ├── subdomains.py
│   │   │   ├── dns.py
│   │   │   ├── http.py
│   │   │   ├── shodan.py
│   │   │   └── endpoints.py
│   │   └── notifiers/          # Notification channels
│   │       ├── base.py
│   │       ├── slack.py
│   │       ├── discord.py
│   │       └── telegram.py
│   └── utils/
│       ├── cli_tools.py        # Tool wrappers
│       └── helpers.py          # Utility functions
├── web/
│   ├── templates/              # Jinja2 templates
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── project_detail.html
│   │   ├── events.html
│   │   └── 404.html
│   └── static/
│       ├── css/
│       │   └── style.css       # Main stylesheet
│       └── js/
│           └── main.js         # JavaScript utilities
├── cli.py                      # Standalone CLI tool
├── requirements.txt
├── .env.example
├── setup_tools.sh
├── verify_tools.sh
├── configure_apis.sh
└── README.md
```

## 💡 Usage Examples

### Create Project via UI

1. Navigate to http://localhost:8000
2. Click "New Project"
3. Fill in details:
   ```
   Name: My Company
   Description: Main domain monitoring
   Domains: example.com, example.org
   ```
4. Configure tools (all enabled by default)
5. Setup notifications (optional)
6. Click "Create"

### Create Project via API

```bash
curl -X POST http://localhost:8000/api/projects \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Company",
    "description": "Main domain monitoring",
    "domains": ["example.com", "example.org"],
    "config": {
      "enabled_tools": {
        "subdomains": {"enabled": true, "sources": ["subfinder", "assetfinder"]},
        "dns": {"enabled": true},
        "http": {"enabled": true, "threads": 50},
        "shodan": {"enabled": true},
        "endpoints": {"enabled": true, "sources": ["waybackurls", "gau"]}
      }
    },
    "notification_config": {
      "slack": {
        "enabled": true,
        "webhook_url": "https://hooks.slack.com/...",
        "min_severity": "medium"
      }
    }
  }'
```

### Trigger Manual Scan

**Via UI:**
- Go to project detail page
- Click "Run Scan" or "Weekly Scan"

**Via API:**
```bash
curl -X POST http://localhost:8000/api/scans/trigger \
  -H "Content-Type: application/json" \
  -d '{"project_id": 1, "mode": "normal"}'
```

### Schedule Automatic Scans

**Via API:**
```bash
# Daily scan at 2 AM
curl -X POST "http://localhost:8000/api/scans/schedule?project_id=1&cron_expression=0%202%20*%20*%20*&scan_mode=normal"

# Weekly scan on Sunday at 3 AM
curl -X POST "http://localhost:8000/api/scans/schedule?project_id=1&cron_expression=0%203%20*%20*%200&scan_mode=weekly"
```

**Via Database (on startup):**

Edit project config in database:
```json
{
  "schedule": {
    "normal": "0 2 * * *",
    "normal_enabled": true,
    "weekly": "0 3 * * 0",
    "weekly_enabled": true
  }
}
```

### View Events

**Via UI:**
- Navigate to /events
- Filter by severity, type, or project
- Click event to view details
- Acknowledge events

**Via API:**
```bash
# Get high severity events from last 7 days
curl "http://localhost:8000/api/events?severity=high&days=7"

# Get events for specific project
curl "http://localhost:8000/api/events?project_id=1"

# Get event statistics
curl "http://localhost:8000/api/events/stats"
```

### Acknowledge Events

**Via UI:**
- Go to events page
- Click checkmark button on event

**Via API:**
```bash
curl -X PATCH http://localhost:8000/api/events/123 \
  -H "Content-Type: application/json" \
  -d '{"acknowledged": true, "acknowledged_by": "admin"}'
```

## 🔔 Notification Configuration

### Slack

1. Create Slack App di https://api.slack.com/apps
2. Enable Incoming Webhooks
3. Add webhook URL to project config atau .env

Example notification:
```
🔍 Asset Monitor: My Company (normal scan)

10 events detected

🔴 CRITICAL: 2  🟠 HIGH: 3  🟡 MEDIUM: 5

────────────────

🔴 CRITICAL - takeover_suspected
Subdomain takeover suspected: blog.example.com -> old.netlify.app (Netlify)

🟠 HIGH - vulnerability_found
New vulnerability found on 1.2.3.4: CVE-2023-1234
```

### Discord

Similar to Slack, tapi dengan Discord webhook URL.

### Telegram

1. Create bot via @BotFather
2. Get bot token
3. Get chat ID (send message to bot, then get updates)
4. Configure in project settings

## 📊 Database Schema

### Projects
- id, name, description
- config (JSON)
- notification_config (JSON)
- last_scan_at, last_weekly_scan_at
- is_active

### Domains
- id, project_id, name
- is_active

### Snapshots
- id, project_id, type
- data (JSON)
- metadata (JSON)
- created_at

Snapshot types:
- `subdomains`: List of discovered subdomains
- `dns`: DNS records (A, CNAME)
- `http`: HTTP probe results
- `shodan`: Shodan scan results
- `endpoints`: URLs and JS files

### Events
- id, project_id, type, severity
- summary, details (JSON)
- related_entities (JSON)
- seen, acknowledged
- notified
- created_at

Event types:
- `subdomain_new`, `subdomain_removed`
- `dns_changed`
- `http_status_changed`, `http_title_changed`, `http_content_changed`
- `port_new`, `port_removed`
- `vulnerability_found`
- `endpoint_new`, `js_file_new`
- `takeover_suspected`

### ScanLog
- id, project_id
- scan_mode, status
- started_at, completed_at
- events_generated
- tools_executed (JSON)
- errors (JSON)

## 🎯 Scan Workflow

1. **Orchestrator receives scan request**
   - Load project and domains
   - Create scan log
   - Initialize notification manager

2. **Execute scanners in order:**
   - Subdomain discovery (subfinder, assetfinder, crt.sh)
   - DNS monitoring (dnsx)
   - HTTP probing (httpx)
   - Shodan scanning (if enabled)
   - Endpoint discovery (if weekly mode)

3. **For each scanner:**
   - Run tool and collect data
   - Load previous snapshot
   - Run diff logic
   - Generate events
   - Save new snapshot

4. **After all scanners:**
   - Save all events to database
   - Send notifications (filtered by severity)
   - Update scan log
   - Update project last_scan_at

## 🔧 Maintenance

### View Logs

```bash
tail -f assetmon.log
```

### Database Migrations

```bash
# If using Alembic
alembic revision --autogenerate -m "Description"
alembic upgrade head
```

### Clear Old Data

```bash
# Delete old snapshots (keep last 30 days)
python -c "
from app.db import SessionLocal
from app.models import Snapshot
from datetime import datetime, timedelta

db = SessionLocal()
cutoff = datetime.utcnow() - timedelta(days=30)
db.query(Snapshot).filter(Snapshot.created_at < cutoff).delete()
db.commit()
"
```

### Backup Database

```bash
# SQLite backup
cp assetmon.db assetmon_backup_$(date +%Y%m%d).db
```

## 🐛 Troubleshooting

### Web server won't start

```bash
# Check if port 8000 is available
lsof -i :8000

# Use different port
uvicorn app.main:app --port 8001
```

### Database errors

```bash
# Reinitialize database
rm assetmon.db
python -c "from app.db import init_db; init_db()"
```

### Scheduled jobs not running

```bash
# Check job status via API
curl http://localhost:8000/api/scans/scheduled

# Check logs
grep "scheduler" assetmon.log
```

### Notifications not sending

```bash
# Test notification config
curl -X POST http://localhost:8000/api/scans/trigger \
  -H "Content-Type: application/json" \
  -d '{"project_id": 1, "mode": "normal"}'

# Check notification settings in project config
# Verify webhook URLs are correct
```

## 🎓 Advanced Topics

### Custom Scan Configuration

Edit project config to customize scanner behavior:

```json
{
  "enabled_tools": {
    "subdomains": {
      "enabled": true,
      "sources": ["subfinder", "assetfinder", "crtsh"]
    },
    "dns": {
      "enabled": true,
      "rate_limit": 100
    },
    "http": {
      "enabled": true,
      "threads": 50,
      "timeout": 10
    },
    "shodan": {
      "enabled": true,
      "query_mode": "ip"
    },
    "endpoints": {
      "enabled": true,
      "sources": ["waybackurls", "gau"],
      "weekly_only": true
    }
  }
}
```

### Adding New Notification Channels

1. Create new notifier class in `app/services/notifiers/`
2. Extend `BaseNotifier`
3. Implement `send()` method
4. Register in orchestrator

### Extending Scan Logic

1. Add new scanner in `app/services/scanner/`
2. Add diff logic in `app/services/diff/`
3. Update orchestrator to include new scanner
4. Add new event types in models if needed

## 📝 Summary

Platform ini sekarang fully functional dengan:
- ✅ Web UI untuk management
- ✅ Background job scheduling
- ✅ Multi-channel notifications
- ✅ Complete REST API
- ✅ Subdomain takeover detection
- ✅ Shodan vulnerability scanning
- ✅ Change tracking dan alerting
- ✅ Easy to maintain dan extend

Ready untuk production use! 🚀
