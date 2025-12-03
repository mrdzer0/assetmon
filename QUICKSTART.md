# Quick Start Guide

Panduan cepat untuk mulai menggunakan Asset Monitor.

## Installation

### 1. Install Tools

Jalankan script otomatis untuk install semua required CLI tools:

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

Atau gunakan CLI:

```bash
python cli.py verify
```

### 3. Configure API Keys

```bash
./configure_apis.sh
```

Atau manual:

```bash
# Shodan API (required untuk vulnerability scanning)
shodan init YOUR_SHODAN_API_KEY

# Copy .env example
cp .env.example .env

# Edit .env dan tambahkan API keys
nano .env
```

### 4. Install Python Dependencies

```bash
pip install -r requirements.txt
```

## Usage Examples

### Subdomain Discovery

Discover subdomains untuk target domain:

```bash
python cli.py subdomains -d example.com -o results/subdomains.json
```

Multiple domains:

```bash
python cli.py subdomains -d example.com -d example2.com
```

Pilih specific sources:

```bash
python cli.py subdomains -d example.com -s subfinder -s crtsh
```

### DNS Monitoring & Takeover Detection

Resolve DNS dan detect potential subdomain takeovers:

```bash
# Dari file
python cli.py dns -f results/subdomains.json -o results/dns.json

# Manual input
python cli.py dns -s api.example.com -s www.example.com
```

Output akan menampilkan:
- DNS A records dan CNAME
- **Potential subdomain takeovers** (CNAME pointing to dead services)
- NXDOMAIN dengan CNAME

### HTTP Probing

Probe HTTP endpoints:

```bash
# Dari file
python cli.py http -f subdomains.txt -o results/http.json

# Manual targets
python cli.py http -t https://example.com -t https://api.example.com
```

Options:

```bash
# Custom threads dan timeout
python cli.py http -f targets.txt --threads 100 --timeout 5
```

### Shodan Scanning

Scan dengan Shodan untuk ports dan vulnerabilities:

```bash
# Scan IPs
python cli.py shodan -i 1.2.3.4 -i 5.6.7.8 --mode ip

# Search by domain
python cli.py shodan -d example.com --mode domain
```

**Note**: Requires Shodan API key configured!

### Endpoint Discovery (Weekly Scan)

Discover URLs dan JS files:

```bash
# Basic (waybackurls + gau)
python cli.py endpoints -d example.com -o results/endpoints.json

# Include katana crawler
python cli.py endpoints -d example.com -s waybackurls -s gau -s katana --depth 3

# With subdomains file for katana
python cli.py endpoints -d example.com -f subdomains.txt -s katana
```

**Warning**: Endpoint discovery can take a LONG time, especially with katana!

### Full Scan

Run complete scan (subdomains + DNS + HTTP + Shodan):

```bash
# Normal scan (fast)
python cli.py scan -d example.com --mode normal

# Weekly scan (includes endpoint discovery)
python cli.py scan -d example.com --mode weekly
```

Results akan disimpan di folder dengan timestamp:

```
results/full_scan/
  └── scan_20250102_143022.json
```

## Understanding Results

### Subdomain Takeover Detection

Platform mendeteksi 2 jenis potential takeovers:

#### 1. CNAME Pointing to Dead Services

Terdeteksi di **DNS monitoring**. CNAME yang point ke services berikut:

- Vercel (`*.vercel.app`)
- Netlify (`*.netlify.app`)
- GitHub Pages (`*.github.io`)
- Heroku (`*.herokuapp.com`)
- AWS S3 (`*.s3.amazonaws.com`)
- Azure (`*.azurewebsites.net`)
- Dan lainnya...

Example output:

```json
{
  "subdomain": "blog.example.com",
  "cname": "example.netlify.app",
  "service": "Netlify",
  "reason": "cname_dead_service",
  "severity": "critical"
}
```

#### 2. NXDOMAIN dengan CNAME

CNAME exists tapi tidak resolve ke A record (domain tidak exist).

```json
{
  "subdomain": "old-app.example.com",
  "cname": "old-project.herokuapp.com",
  "reason": "nxdomain_with_cname",
  "severity": "medium"
}
```

### Shodan Vulnerabilities

Output dari Shodan scan:

```json
{
  "ip": "1.2.3.4",
  "ports": [22, 80, 443],
  "vulns": ["CVE-2023-1234", "CVE-2023-5678"],
  "services": [...]
}
```

## CLI Commands Reference

```bash
# Verify tools
python cli.py verify

# Subdomain discovery
python cli.py subdomains -d DOMAIN [OPTIONS]
  -d, --domains DOMAIN     Target domain (can use multiple times)
  -s, --sources SOURCE     Source to use: subfinder, assetfinder, crtsh
  -o, --output FILE        Output file (default: results/subdomains.json)

# DNS monitoring
python cli.py dns [OPTIONS]
  -f, --subdomains-file FILE   File with subdomains (one per line)
  -s, --subdomains SUBDOMAIN   Subdomain to check (can use multiple times)
  -r, --rate-limit N           DNS rate limit
  -o, --output FILE            Output file

# HTTP probing
python cli.py http [OPTIONS]
  -f, --targets-file FILE   File with targets
  -t, --targets TARGET      Target URL/hostname (can use multiple times)
  --threads N               Number of threads
  --timeout N               Timeout per request
  -o, --output FILE         Output file

# Shodan scanning
python cli.py shodan [OPTIONS]
  -i, --ips IP              IP address (can use multiple times)
  -d, --domains DOMAIN      Domain (can use multiple times)
  --mode [ip|domain]        Query mode (default: ip)
  -o, --output FILE         Output file

# Endpoint discovery
python cli.py endpoints -d DOMAIN [OPTIONS]
  -d, --domains DOMAIN           Target domain (can use multiple times)
  -f, --subdomains-file FILE     File with subdomains for crawling
  -s, --sources SOURCE           Source: waybackurls, gau, katana
  --depth N                      Crawl depth for katana (default: 2)
  -o, --output FILE              Output file

# Full scan
python cli.py scan -d DOMAIN [OPTIONS]
  -d, --domains DOMAIN        Target domain (can use multiple times)
  --mode [normal|weekly]      Scan mode (default: normal)
  -o, --output-dir DIR        Output directory
```

## Tips & Best Practices

### 1. Rate Limiting

Jika mendapat rate limiting errors:

```bash
# DNS dengan rate limit
python cli.py dns -f subs.txt --rate-limit 50
```

### 2. Large Scans

Untuk large scans, gunakan normal mode dulu:

```bash
# Fast normal scan
python cli.py scan -d example.com --mode normal

# Weekly scan (slow) hanya ketika perlu
python cli.py scan -d example.com --mode weekly
```

### 3. Shodan API Limits

Free Shodan API limited to 100 results per search. Untuk banyak IPs, gunakan mode `ip` dengan batch processing.

### 4. Workflow Example

Complete workflow untuk monitor domain:

```bash
# 1. Discover subdomains
python cli.py subdomains -d example.com -o results/subs.json

# 2. Check DNS dan detect takeovers
cat results/subs.json | jq -r '.subdomains[]' > results/subs.txt
python cli.py dns -f results/subs.txt -o results/dns.json

# 3. Probe HTTP
python cli.py http -f results/subs.txt -o results/http.json

# 4. Extract IPs dan scan dengan Shodan
cat results/dns.json | jq -r '.dns_records | to_entries[] | .value.a[]' | sort -u > results/ips.txt
python cli.py shodan -i $(cat results/ips.txt | tr '\n' ' ') --mode ip -o results/shodan.json
```

## Troubleshooting

### Tools not found

```bash
# Reload shell
source ~/.bashrc

# Or add Go bin to PATH manually
export PATH=$PATH:$HOME/go/bin

# Verify
which subfinder
which dnsx
```

### Shodan API errors

```bash
# Reinitialize
shodan init YOUR_API_KEY

# Test
shodan info
```

### Permission denied

```bash
# Make scripts executable
chmod +x setup_tools.sh verify_tools.sh configure_apis.sh cli.py
```

## Next Steps

1. **Test dengan small domain first** untuk familiarize dengan tools
2. **Configure notification channels** (Slack, Discord, Telegram) di `.env`
3. **Setup database** dan implement full platform dengan web UI (future work)
4. **Schedule scans** dengan cron untuk continuous monitoring

## Questions?

Refer to main README.md untuk complete documentation atau check source code di `app/services/scanner/`.
