# Asset Monitor

Automated attack surface discovery and monitoring platform. Track changes in your assets, detect vulnerabilities, and get notified.

## Features

- **Subdomain Discovery** — Multiple sources (subfinder, assetfinder, crt.sh, chaos)
- **DNS & HTTP Monitoring** — Track record changes, status codes, technologies
- **Port Scanning** — Detect open ports with optional screenshots
- **Vulnerability Scanning** — Nuclei integration for CVE detection
- **Subdomain Takeover Detection** — CNAME pointing to dead services
- **Endpoint Discovery** — Historical URLs via waybackurls, gau, katana
- **Scheduled Scans** — Automated daily/weekly reconnaissance
- **Notifications** — Discord, Telegram, Slack integration
- **Web Dashboard** — Manage projects and view findings

## Quick Start

```bash
# 1. Install security tools
./setup_tools.sh
source ~/.bashrc

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
nano .env

# 4. Start the application
./start_web.sh
```

Access at `http://localhost:8000`

## Scan Modes

| Mode | Modules | Use Case |
|------|---------|----------|
| **Normal** | Subdomain, DNS, HTTP | Daily monitoring |
| **Weekly** | All + Ports, Nuclei, Endpoints | Full assessment |
| **Custom** | User-selected | Targeted scans |

## Integrated Tools

| Category | Tools |
|----------|-------|
| Subdomain | subfinder, assetfinder, crt.sh, chaos |
| DNS/HTTP | dnsx, httpx |
| Ports | naabu, Shodan |
| Endpoints | waybackurls, gau, katana |
| Vuln Scan | nuclei |

## Configuration

Edit `.env` for API keys and settings:

```ini
SHODAN_API_KEY=your_key
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

Scanner settings available at `/settings/scanners` in the web UI.

## Documentation

See the [Documentation](Documentation/) folder for detailed guides:
- [Installation Guide](Documentation/INSTALLATION.md)
- [Configuration](Documentation/CONFIGURATION.md)
- [Usage Guide](Documentation/USAGE.md)

## Database Migration

For existing installations after updates:

```bash
python migrate_db.py
```

## License

MIT
