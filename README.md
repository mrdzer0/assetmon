# Asset Monitor

Platform untuk monitoring attack surface dan mendeteksi perubahan assets secara otomatis.

## Features

- **Subdomain Discovery**: Menggunakan multiple sources (subfinder, assetfinder, crt.sh, chaos, amass)
- **DNS Monitoring**: Track perubahan A records dan CNAME menggunakan dnsx
- **HTTP Monitoring**: Monitor status code, title, content length, technologies dengan httpx
- **Subdomain Takeover Detection**: Deteksi CNAME pointing ke dead services (Vercel, Netlify, GitHub Pages, Heroku, AWS S3, Azure, dll)
- **Port Scanning**: Integrasi dengan Shodan API untuk detect new ports dan vulnerabilities
- **Endpoint Discovery**: Collect URLs dan JS files menggunakan waybackurls, gau, katana
- **Change Detection**: Automatic diff untuk detect perubahan dan generate alerts
- **Multi-Channel Notifications**: Support Slack, Discord, Telegram
- **Web UI**: Dashboard dan configuration interface
- **Scan Modes**: Normal scan (daily) vs Weekly scan (dengan heavy crawlers)

## Quick Start

### 1. Install Tools

Jalankan script otomatis untuk install semua required tools:

```bash
./setup_tools.sh
```

Script ini akan install:
- Go (jika belum ada)
- subfinder, assetfinder, dnsx, httpx
- waybackurls, gau, katana
- shodan Python package

### 2. Verify Installation

```bash
./verify_tools.sh
```

### 3. Configure API Keys

```bash
./configure_apis.sh
```

Atau manual:

```bash
# Shodan API
shodan init YOUR_SHODAN_API_KEY

# Copy dan edit .env
cp .env.example .env
nano .env
```

### 4. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the Platform

**Option A: Web Platform (Recommended)**
```bash
# Initialize database
python -c "from app.db import init_db; init_db()"

# Run web server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Access dashboard
open http://localhost:8000
```

Features:
- Dashboard dengan project overview
- Create dan manage projects via UI
- Trigger scans (normal/weekly) dengan one click
- View events dan snapshots
- Schedule automatic scans
- Real-time notifications

**Option B: CLI Tool (For quick testing)**
```bash
# Direct scanning without database
python cli.py scan --domain example.com --mode normal

# Or use individual commands
python cli.py subdomains -d example.com
python cli.py dns -f subdomains.txt
python cli.py http -f targets.txt
```

## Project Structure

```
assetmon/
├── app/
│   ├── config.py              # Configuration management
│   ├── db.py                  # Database setup
│   ├── models.py              # SQLAlchemy models
│   ├── schemas.py             # Pydantic schemas
│   ├── services/
│   │   ├── scanner/           # Scanning services
│   │   │   ├── subdomains.py
│   │   │   ├── dns_monitor.py
│   │   │   ├── http_monitor.py
│   │   │   ├── shodan_monitor.py
│   │   │   ├── endpoints.py
│   │   │   └── takeover.py
│   │   ├── diff/              # Change detection logic
│   │   └── notifiers/         # Notification channels
│   ├── utils/
│   │   └── cli_tools.py       # Subprocess wrappers
│   └── routers/               # FastAPI endpoints
├── web/
│   ├── templates/             # Jinja2 templates
│   └── static/                # CSS/JS
├── tests/
├── setup_tools.sh             # Auto install tools
├── verify_tools.sh            # Verify installations
├── configure_apis.sh          # Configure API keys
├── requirements.txt
└── README.md
```

## Tools Reference

### Subdomain Discovery
- **subfinder**: Passive subdomain discovery
- **assetfinder**: Find domains and subdomains
- **crt.sh**: Certificate transparency logs
- **chaos**: ProjectDiscovery chaos dataset
- **amass**: Comprehensive subdomain enumeration (optional, heavy)

### DNS & HTTP Probing
- **dnsx**: Fast DNS toolkit
- **httpx**: HTTP probing and data extraction

### Endpoint Discovery
- **waybackurls**: URLs from Wayback Machine
- **gau**: GetAllUrls from multiple sources
- **katana**: Web crawling framework

### Vulnerability Scanning
- **shodan**: Search engine for Internet-connected devices

## Subdomain Takeover Detection

Platform ini mendeteksi potential subdomain takeover dengan 2 metode:

### 1. CNAME Pointing to Dead Services
Menggunakan hasil dari `dnsx`, deteksi CNAME yang point ke services berikut:
- Vercel (`*.vercel.app`)
- Netlify (`*.netlify.app`)
- GitHub Pages (`*.github.io`)
- Heroku (`*.herokuapp.com`)
- AWS S3 (`*.s3.amazonaws.com`)
- Azure (`*.azurewebsites.net`)
- CloudFront (`*.cloudfront.net`)

### 2. DNS NXDOMAIN dengan CNAME
Subdomain yang memiliki CNAME record tapi resolve ke NXDOMAIN (domain tidak exist)

### Configuration
Edit patterns di `.env`:
```bash
TAKEOVER_PATTERNS_CNAME=vercel.app,netlify.app,github.io,herokuapp.com
TAKEOVER_FINGERPRINTS=There isn't a GitHub Pages site here,No such app
```

## Shodan Integration

Untuk vulnerability detection dari Shodan:

1. **Port Scanning**: Detect new open ports
2. **Vulnerability Data**: CVE information jika tersedia
3. **Service Detection**: Banner grabbing dan service identification
4. **Rate Limiting**: Free API key limited to 100 results/search

## Scan Modes

### Normal Scan (Daily)
Cepat, tidak menggunakan heavy crawlers:
- Subdomain discovery
- DNS probing
- HTTP probing
- Shodan query
- Subdomain takeover detection

### Weekly Scan
Comprehensive, termasuk endpoint discovery:
- Semua yang ada di normal scan
- waybackurls untuk historical URLs
- gau untuk comprehensive URL collection
- katana untuk active crawling

## Development Status

✅ **Completed**
- Project structure
- Installation scripts
- Configuration management

🚧 **In Progress**
- Core scanning services
- Database models
- CLI tools wrappers

📋 **Planned**
- Diff logic
- Notification system
- Web UI
- Background job scheduling

## Contributing

This is a learning project. Feel free to extend or modify as needed.

## License

MIT

## Web UI Usage

### Creating a Project

1. Access dashboard di http://localhost:8000
2. Click "New Project"
3. Fill in project details:
   - **Name**: Project identifier
   - **Description**: Optional description
   - **Domains**: Root domains to monitor (e.g., example.com)
4. Configure enabled tools and scan settings
5. Setup notification channels (Slack, Discord, Telegram)

### Running Scans

#### Manual Scan
- Navigate to project detail page
- Click "Run Scan" for normal scan
- Click "Weekly Scan" for comprehensive scan dengan endpoint discovery

#### Scheduled Scans
Scans can be scheduled automatically using cron expressions:

```python
# Via API
POST /api/scans/schedule
{
  "project_id": 1,
  "cron_expression": "0 2 * * *",  // Daily at 2 AM
  "scan_mode": "normal"
}
```

Default schedules:
- **Normal scan**: Daily at 2 AM (`0 2 * * *`)
- **Weekly scan**: Sunday at 3 AM (`0 3 * * 0`)

### Viewing Results

#### Dashboard
- Overview semua projects
- Today's events statistics
- Recent scan history
- Quick access to projects

#### Project Detail Page
- Latest snapshots (subdomains, DNS, HTTP, Shodan, endpoints)
- Recent events dengan severity indicators
- Scan history dan statistics

#### Events Page
- All events dari semua projects
- Filter by severity, type, project
- Acknowledge events untuk tracking
- View detailed event information

### Notifications

Platform supports 3 notification channels:

#### 1. Slack
```bash
# Configure via project settings atau .env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

#### 2. Discord
```bash
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK
```

#### 3. Telegram
```bash
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

Notifications include:
- Event summary dengan severity counts
- Detailed event list (up to 10 events)
- Project name dan scan mode
- Formatted dengan colors dan emojis

### API Endpoints

Complete REST API untuk automation:

#### Projects
- `GET /api/projects` - List all projects
- `POST /api/projects` - Create project
- `GET /api/projects/{id}` - Get project details
- `PUT /api/projects/{id}` - Update project
- `DELETE /api/projects/{id}` - Delete project

#### Scans
- `POST /api/scans/trigger` - Trigger manual scan
- `GET /api/scans/logs` - Get scan logs
- `POST /api/scans/schedule` - Schedule recurring scan
- `DELETE /api/scans/schedule/{job_id}` - Remove scheduled scan
- `GET /api/scans/scheduled` - List scheduled scans

#### Events
- `GET /api/events` - List events (with filters)
- `GET /api/events/{id}` - Get event details
- `PATCH /api/events/{id}` - Update event (acknowledge)
- `POST /api/events/bulk-update` - Bulk update events
- `GET /api/events/stats` - Get event statistics

#### Snapshots
- `GET /api/snapshots` - List snapshots
- `GET /api/snapshots/{id}` - Get snapshot details
- `GET /api/snapshots/latest/{project_id}` - Get latest snapshots

Example API usage:
```bash
# Trigger scan
curl -X POST http://localhost:8000/api/scans/trigger \
  -H "Content-Type: application/json" \
  -d '{"project_id": 1, "mode": "normal"}'

# Get events
curl http://localhost:8000/api/events?severity=high&days=7

# Acknowledge event
curl -X PATCH http://localhost:8000/api/events/123 \
  -H "Content-Type: application/json" \
  -d '{"acknowledged": true}'
```

