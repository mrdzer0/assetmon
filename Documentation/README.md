# Asset Monitor - Documentation

Welcome to Asset Monitor, an automated asset discovery and monitoring platform.

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [INSTALLATION.md](INSTALLATION.md) | Installation guide and prerequisites |
| [CONFIGURATION.md](CONFIGURATION.md) | Scanner and system configuration |
| [USAGE.md](USAGE.md) | User guide and features |
| [CELERY_SETUP.md](CELERY_SETUP.md) | Background task queue setup |

## 🚀 Quick Start

```bash
# Install tools
./scripts/setup_tools.sh
source ~/.bashrc

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
nano .env

# Start
./start.sh
```

## 🔧 Key Files

| File | Purpose |
|------|---------|
| `start.sh` | Start web + worker |
| `scripts/setup_tools.sh` | Install security tools |
| `scripts/migrate_db.py` | Database migrations |
| `manage_users.py` | User management CLI |
| `.env` | Environment configuration |

## 🛡️ Security Tools

Asset Monitor integrates with:

- **Subfinder** - Subdomain enumeration
- **DNSx** - DNS resolution
- **HTTPx** - HTTP probing
- **Naabu** - Port scanning
- **Nuclei** - Vulnerability scanning
- **Shodan** - Internet intelligence
- **GAU/Katana** - Endpoint discovery

## 📊 Features

- ✅ Automated subdomain discovery
- ✅ DNS monitoring
- ✅ HTTP change detection
- ✅ Port scanning with screenshots
- ✅ Vulnerability scanning
- ✅ Scheduled scans
- ✅ Multi-channel notifications
- ✅ PDF reports

## 🆘 Support

For issues and questions:
1. Check troubleshooting in [INSTALLATION.md](INSTALLATION.md)
2. Review logs in `assetmon.log`
3. Create GitHub issue
