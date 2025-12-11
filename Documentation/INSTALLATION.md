# Asset Monitor - Installation Guide

## Prerequisites

- **OS**: Ubuntu 20.04+ / Debian 11+
- **RAM**: Minimum 2GB (4GB recommended)
- **Disk**: 10GB free space
- **Python**: 3.8+
- **Internet**: Required for tool installation

## Quick Install

```bash
# 1. Clone repository
git clone https://github.com/yourusername/assetmon.git
cd assetmon

# 2. Install security tools
chmod +x scripts/setup_tools.sh
./scripts/setup_tools.sh

# 3. Reload shell (important!)
source ~/.bashrc

# 4. Create Python virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# 5. Install Python dependencies
pip install -r requirements.txt

# 6. Configure environment
cp .env.example .env
nano .env  # Edit with your settings

# 7. Start the application
./start.sh
```

## Detailed Installation Steps

### 1. Security Tools Installation

The `setup_tools.sh` script automatically installs:

| Tool | Purpose |
|------|---------|
| Go | Required for Go-based tools |
| Subfinder | Subdomain discovery |
| Assetfinder | Related subdomain discovery |
| DNSx | DNS resolution |
| HTTPx | HTTP probing & screenshots |
| Waybackurls | Historical URL discovery |
| GAU | URL discovery from archives |
| Katana | Web crawling |
| Naabu | Port scanning |
| Nuclei | Vulnerability scanning |
| Chromium | Screenshot capture |
| Redis | Background task broker |
| Celery | Task queue worker |

### 2. Environment Configuration

Edit `.env` file with your settings:

```ini
# Database
DATABASE_URL=sqlite:///./assetmon.db

# API Keys (optional but recommended)
SHODAN_API_KEY=your_shodan_key

# Notification (optional)
DISCORD_WEBHOOK_URL=your_discord_webhook
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Server
HOST=0.0.0.0
PORT=8000
```

### 3. Database Initialization

The database is automatically created on first run. For existing installations with new features:

```bash
python scripts/migrate_db.py
```

### 4. User Management

```bash
# Create admin user
python manage_users.py user create admin --password yourpassword --role admin

# List users
python manage_users.py user list
```

## Verification

Run the check script to verify installation:

```bash
./scripts/check_setup.sh
```

## Running the Application

### Development Mode
```bash
./start.sh
# This starts both Celery worker and web server
# or for web server only:
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Production Mode
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

Access the web interface at: `http://localhost:8000`

## Troubleshooting

### Go tools not found
```bash
source ~/.bashrc
export PATH=$PATH:$HOME/go/bin
```

### Chromium not working for screenshots
```bash
sudo apt install -y chromium-browser
# or
sudo apt install -y chromium
```

### Database errors after update
```bash
python scripts/migrate_db.py
```

## Next Steps

See [CONFIGURATION.md](CONFIGURATION.md) for detailed scanner configuration options.
