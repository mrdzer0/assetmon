# Asset Monitor - Usage Guide

## Getting Started

### 1. Create a Project

1. Navigate to **Dashboard** → **New Project**
2. Enter:
   - **Name**: Project identifier (e.g., "Company Assets")
   - **Root Domains**: Target domains, one per line (e.g., `example.com`)
3. Click **Create Project**

### 2. Run Your First Scan

From the project detail page:

1. Click **Run Scan** button
2. Select scan type:
   - **Normal**: Subdomain + DNS + HTTP (fast)
   - **Weekly**: Full scan including ports, nuclei, etc.
   - **Custom**: Select specific modules

---

## Scan Types

### Normal Scan
Fast daily reconnaissance:
- ✅ Subdomain Discovery
- ✅ DNS Resolution
- ✅ HTTP Probing
- ⚙️ Optional modules (configurable)

### Weekly Scan
Comprehensive security assessment:
- ✅ All Normal Scan modules
- ✅ Port Scanning
- ✅ Endpoint Discovery
- ✅ Shodan Lookup
- ✅ Nuclei Vulnerability Scan

### Custom Scan
Select specific modules to run:
- Pick individual scanners
- Useful for targeted assessments

---

## Features

### Dashboard
- Overview of all projects
- Quick scan buttons
- Event timeline
- Statistics

### Project Details
Navigation tabs:
- **Assets**: Discovered subdomains and HTTP info
- **DNS**: DNS resolution records
- **Events**: Security findings and changes
- **Ports**: Open ports and services
- **Vulnerabilities**: Nuclei findings
- **Endpoints**: Discovered URLs
- **Scans**: Scan history and logs

### Events
Types of security events:
- 🆕 New subdomains discovered
- 🔓 Open ports detected
- ⚠️ Vulnerabilities found
- 📊 Status code changes
- 🔧 Technology changes

### Reports
Generate PDF reports:
1. Go to project detail page
2. Click **Export** → **PDF Report**
3. Select date range and sections

---

## Scheduling Scans

### Create Schedule
1. Go to **Schedules** page
2. Click **Add Schedule**
3. Configure:
   - Project to scan
   - Scan mode (Normal/Weekly)
   - Cron expression

### Common Schedules
| Schedule | Cron | Description |
|----------|------|-------------|
| Daily 2AM | `0 2 * * *` | Every day at 2:00 AM |
| Weekly Sunday | `0 3 * * 0` | Sunday at 3:00 AM |
| Every 12 hours | `0 */12 * * *` | Twice daily |

---

## Notifications

### Discord
1. Create Discord webhook
2. Add to Settings → Notifications
3. Events are posted to channel

### Telegram
1. Create bot via @BotFather
2. Get chat ID
3. Configure in Settings

### Slack
1. Create Slack webhook
2. Add to Settings → Notifications

---

## Tips & Best Practices

### Performance
- Start with small targets
- Use custom scans for specific needs
- Schedule heavy scans during off-hours

### Accuracy
- Verify critical findings manually
- Check for false positives
- Review nuclei severity levels

### Organization
- Use descriptive project names
- Group related domains
- Regular schedule reviews

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl + K` | Quick search |
| `Esc` | Close modal |

---

## API Access

Asset Monitor provides REST API endpoints.

### Authentication
```bash
curl -X POST /api/auth/login \
  -d '{"username":"admin","password":"pass"}'
```

### Trigger Scan
```bash
curl -X POST /api/scan/trigger \
  -H "Authorization: Bearer TOKEN" \
  -d '{"project_id":1,"mode":"normal"}'
```

See [API.md](API.md) for complete API documentation.
