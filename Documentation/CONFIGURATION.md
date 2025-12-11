# Asset Monitor - Configuration Guide

## Scanner Configuration

Access via: **Settings → Scanner Configuration** (`/settings/scanners`)

### Scan Mode Configuration

Controls which modules run in scheduled scans:

| Module | Normal (Daily) | Weekly |
|--------|:--------------:|:------:|
| Subdomain Discovery | ✅ Always | ✅ Always |
| DNS Resolution | ✅ Always | ✅ Always |
| HTTP Probing | ✅ Always | ✅ Always |
| Port Scanning | ⚙️ Optional | ✅ Default ON |
| Endpoint Discovery | ⚙️ Optional | ✅ Default ON |
| Shodan Lookup | ⚙️ Optional | ✅ Default ON |
| Nuclei Scan | ⚙️ Optional | ✅ Default ON |

### Subdomain Discovery Sources

| Source | Description | Default |
|--------|-------------|:-------:|
| Subfinder | Fast passive enumeration | ✅ |
| Assetfinder | Related subdomains | ✅ |
| Amass | Comprehensive OSINT (slow) | ❌ |
| crt.sh | Certificate transparency | ✅ |
| Chaos | ProjectDiscovery dataset | ✅ |

### DNS Configuration

| Setting | Default | Description |
|---------|:-------:|-------------|
| Rate Limit | 100/s | Queries per second |
| Record Types | A, AAAA, CNAME, MX, TXT | DNS records to resolve |

### HTTP Configuration

| Setting | Default | Description |
|---------|:-------:|-------------|
| Threads | 50 | Concurrent requests |
| Timeout | 10s | Request timeout |
| Follow Redirects | ✅ | Follow HTTP redirects |

### Port Scanning (Naabu)

| Setting | Default | Description |
|---------|:-------:|-------------|
| Enabled | ✅ | Enable port scanning |
| Ports | 8080,8443,8000... | Ports to scan |
| Rate | 1000 | Packets per second |
| Screenshots | ❌ | Capture screenshots |

### Nuclei Configuration

| Setting | Default | Description |
|---------|:-------:|-------------|
| Enabled | ✅ | Enable vulnerability scanning |
| Severity Filter | critical, high, medium | Minimum severity |
| Concurrency | 25 | Parallel templates |

### Endpoint Discovery

| Source | Default | Description |
|--------|:-------:|-------------|
| Waybackurls | ✅ | Wayback Machine URLs |
| GAU | ✅ | Google, Archive URLs |
| Katana | ✅ | Web crawler |

---

## Environment Variables

Configure in `.env` file:

### Database
```ini
DATABASE_URL=sqlite:///./assetmon.db
# or for PostgreSQL:
# DATABASE_URL=postgresql://user:pass@localhost:5432/assetmon
```

### API Keys
```ini
SHODAN_API_KEY=your_key_here
```

### Notifications
```ini
# Discord
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

# Telegram
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

### Server Settings
```ini
HOST=0.0.0.0
PORT=8000
LOG_LEVEL=INFO
LOG_FILE=assetmon.log
```

### Tool Timeouts
```ini
TOOL_TIMEOUT=300  # 5 minutes default
```

---

## Custom Tool Paths

If tools are installed in non-standard locations:

```ini
SUBFINDER_PATH=/custom/path/subfinder
HTTPX_PATH=/custom/path/httpx
NUCLEI_PATH=/custom/path/nuclei
NAABU_PATH=/custom/path/naabu
```

---

## Scheduled Scans

Configure via **Schedules** page (`/schedules`):

### Cron Expression Format
```
┌───────────── minute (0-59)
│ ┌─────────── hour (0-23)
│ │ ┌───────── day of month (1-31)
│ │ │ ┌─────── month (1-12)
│ │ │ │ ┌───── day of week (0-6, 0=Sunday)
│ │ │ │ │
* * * * *
```

### Examples
| Expression | Schedule |
|------------|----------|
| `0 2 * * *` | Daily at 2:00 AM |
| `0 3 * * 0` | Sunday at 3:00 AM |
| `0 */6 * * *` | Every 6 hours |
| `30 1 * * 1-5` | Weekdays at 1:30 AM |
