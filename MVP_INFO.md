You are a senior Python full-stack engineer and security engineer.

I want you to design and implement a **minimal but production-ready MVP** for an **attack surface / asset change monitoring platform** with a **web-based UI**.

The platform’s goal:

* Monitor a list of domains and detect changes over time.
* Store snapshots and show historical and current data.
* Generate alerts when changes happen.
* Allow me to manage configuration from a web UI (projects, domains, notification channels, scan options).

---

## 1. High-level requirements

### 1.1. Monitoring scope

For each configured project (e.g., “my-company-main”), with one or more root domains:

1. **Subdomain and status changes**

   * Discover subdomains using external tools (run as subprocess):

     * `subfinder`
     * `assetfinder`
     * `crt.sh` (API or scraping)
     * `chaos`
     * `amass`
   * Aggregate unique subdomains per project.
   * Detect:

     * New subdomains (appeared since last scan)
     * Removed subdomains (no longer present)

2. **DNS pointing changes**

   * For subdomains found above, use `dnsx` to collect:

     * A records (IP addresses)
     * CNAME
   * Detect changes in:

     * A records
     * CNAME
   * Mark them as “dns_changed” events.

3. **HTTP status / metadata changes**

   * For subdomains / URLs, use `httpx` with configurable arguments to collect:

     * status code
     * title
     * content length
     * technologies (tech-detect)
     * headers (optional)
     * IP
     * CNAME
     * EFQDN (if available)
     * ASN
     * CDN
   * Detect changes in:

     * Status code
     * Title
     * Possibly major changes in content length (e.g., ±XX%).

4. **New open ports from Shodan**

   * Integrate Shodan via its API (given `SHODAN_API_KEY`).
   * For each IP / domain of interest, fetch:

     * Open ports
   * Detect newly seen ports compared to last snapshot.

5. **Subdomain takeover / vuln detection (simple MVP)**

   * For now, implement a very simple placeholder check:

     * A set of regex signatures in HTTP response body or title (e.g., classic takeover fingerprints).
   * Any suspected takeover is flagged as a “high severity” event.

6. **New endpoints / JS file detected**

   * Use:

     * `waybackurls`
     * `gau`
     * `katana`
   * Collect URLs per domain.
   * Detect newly seen URLs.
   * Distinguish:

     * General endpoints (paths, APIs, etc).
     * JS files (URLs ending in `.js`).
   * JS URLs should be treated with higher importance.

### 1.2. Weekly vs normal scan

* Some tools are heavy (e.g., waybackurls / gau / katana).
* I want to be able to run:

  * “normal scan” (e.g., daily): no heavy crawling.
  * “weekly scan”: includes the heavy endpoint crawlers.
* Internally track `last_run` timestamps per tool per project to support this logic if needed.

I will trigger the Python app via CLI or an HTTP endpoint (e.g., `POST /api/scan?mode=weekly`). Cron or an external scheduler can call these.

---

## 2. Architecture & tech stack

I want a **modular, configurable, web-based MVP** with **clean structure**.

### 2.1. Tech preferences

* **Backend**:

  * Python 3.x
  * Use **FastAPI** (preferred) or Flask for REST API + minimal server-side rendered pages where needed.

* **Data storage**:

  * Use **SQLite** for MVP (SQLAlchemy models).
  * Store:

    * Projects and config
    * Snapshots (subdomains, DNS, HTTP, Shodan, endpoints)
    * Events / alerts
    * Timestamps for last scans per project & tool

* **Frontend / UI**:

  * Simple but clean web UI:

    * Can be server-side rendered templates (e.g., Jinja2) OR a small frontend (e.g., HTMX / minimal React) – choose something fast to implement.
  * Focus on usability, not on perfect design.

* **Task execution**:

  * For MVP, it’s enough to have synchronous scans triggered via:

    * CLI command
    * OR HTTP endpoint that runs scan inline.
  * But design code so it’s easy to later swap to a background job system (Celery / RQ / APScheduler).

* **External tools**:

  * Wrap `subfinder`, `assetfinder`, `chaos`, `amass`, `dnsx`, `httpx`, `waybackurls`, `gau`, `katana` as subprocess calls.
  * Put all subprocess logic in utility modules with robust error handling (non-zero exit codes, timeouts, etc.).

---

## 3. Configuration & data model

### 3.1. Core concepts

* **Project**

  * `id`
  * `name`
  * `description`
  * `domains` (one-to-many relation with a Domain table, or a JSON list)
  * `enabled_tools` configuration:

    * subdomains: enabled, selected sources
    * dns: enabled
    * http: enabled, httpx args
    * shodan: enabled, query mode, limits
    * endpoints: enabled, tools list, weekly_only flag
  * Notification settings for this project (channels, severity filters, etc).

* **Domain**

  * `id`
  * `project_id`
  * `name` (e.g., `example.com`)

* **Snapshot**

  * `id`
  * `project_id`
  * `created_at`
  * `type` (e.g., `subdomains`, `dns`, `http`, `shodan`, `endpoints`)
  * `data` JSON (to keep MVP simpler)
  * Possibly a pointer to previous snapshot for convenience.

* **Event / Alert**

  * `id`
  * `project_id`
  * `created_at`
  * `type` (`subdomain_new`, `dns_changed`, `status_changed`, `port_new`, `endpoint_new`, `takeover_suspected`, etc.)
  * `severity` (`info`, `low`, `medium`, `high`)
  * `summary` (message shown in UI & notifications)
  * `details` JSON (raw diff, old/new values, etc.)
  * `seen` / `acknowledged` flag.

* **Notification config**

  * For now, store inside project config (e.g. JSON column) or separate tables, your choice, but make it easy to extend later.

### 3.2. Web-based configuration

Create a **web-based configuration UI** where I can:

* List all projects.
* Create / edit projects:

  * Set project name, description.
  * Add / remove root domains.
  * Toggle tools:

    * subdomain sources
    * DNS monitoring
    * HTTP monitoring (and extra args for httpx)
    * Shodan monitoring (Shodan API mode, max results per scan)
    * Endpoint discovery (waybackurls/gau/katana, weekly_only toggle).
  * Set alerting preferences for this project:

    * Slack, Discord, Telegram configuration (reference shared global tokens, or per project).
    * Minimum severity to alert (`info` and above, `medium` and above, etc.).
* View & edit **global config**:

  * Shodan API key
  * Global Slack / Discord / Telegram tokens (if not set per project).

---

## 4. Alerting layer

Design an abstract **Notifier** layer and implement at least these channels:

1. **Slack**

   * Using Webhook URL or bot token.
   * Send aggregated messages per project per scan run.
   * Example message:

     * Project name
     * Scan mode (normal / weekly)
     * For each event:

       * `[SEVERITY] type – short summary (e.g., “New subdomain: api.example.com”)`.

2. **Discord**

   * Using a Discord webhook.
   * Similar structure to Slack.

3. **Telegram**

   * Using Bot token + chat ID.
   * Simple text messages (no need for fancy formatting).

Design requirements:

* Use a **BaseNotifier** abstract class or protocol with a `send(events: List[Event])` method.
* Have concrete implementations for Slack, Discord, Telegram.
* Choose notifications per project based on that project’s configuration.

---

## 5. Scanning & diff logic

Implement a **scan orchestration function** like:

```python
def run_scan(project_id: int, mode: str = "normal") -> List[Event]:
    ...
```

* Steps:

  1. Load project config & domains.
  2. For each enabled tool group:

     * Call subdomain collectors (only if enabled).
     * Call DNS collector using `dnsx`.
     * Call HTTP collector using `httpx`.
     * Call Shodan collector (if enabled and API key exists).
     * If mode is `weekly` and endpoints are configured with `weekly_only`, then run waybackurls/gau/katana.
  3. Load previous snapshot(s) for that project & type.
  4. Compute diffs and generate `Event` objects:

     * New/removed subdomains.
     * DNS changed.
     * HTTP status/title/content-length changed.
     * New Shodan ports per IP.
     * New endpoints & JS URLs.
     * Potential takeovers.
  5. Save new snapshots.
  6. Persist events in DB.
  7. Send alerts using the Notifier layer according to project’s notification config.
  8. Return the list of events.

For diffing, you may design small reusable diff functions per data type, e.g.:

* `diff_subdomains(old: List[str], new: List[str]) -> List[Event]`
* `diff_dns(old: Dict[str, DNSRecord], new: Dict[str, DNSRecord]) -> List[Event]`
* `diff_http(old: Dict[str, HTTPRecord], new: Dict[str, HTTPRecord]) -> List[Event]`
* `diff_shodan(old: Dict[str, ShodanPort], new: Dict[str, ShodanPort]) -> List[Event]`
* `diff_endpoints(old_urls: List[str], new_urls: List[str]) -> List[Event]`

You can keep records in JSON for MVP; no need for super-normalized tables right now.

---

## 6. Web UI Requirements

Implement a minimal web UI with these pages:

1. **Dashboard page**

   * List all projects with:

     * Name
     * Number of domains
     * Last scan time
     * Quick stats (total subdomains, last events count).
   * Button to trigger scan (normal / weekly) for a project.

2. **Project detail page**

   * Show:

     * Project info.
     * List of domains.
     * Last scan status and time.
   * Tabs or sections:

     * **Current subdomains state**

       * Table of subdomains with DNS and HTTP status summary.
     * **Endpoints**

       * Table of endpoints (URLs) and JS files list.
     * **Shodan**

       * Table of IPs and open ports.
     * **Events**

       * Paginated list of recent events:

         * Severity badge, type, summary, created_at.
         * Ability to click into an event to see raw diff (details JSON rendered nicely).

3. **Configuration pages**

   * Project create/edit:

     * Form for name, description, domains, tools toggles, notification settings.
   * Global settings:

     * Shodan API key.
     * Global Slack/Discord/Telegram tokens or webhooks.

---

## 7. Code organization

Please organize the repository with a clean structure, for example:

```text
asset_monitor/
  app/
    __init__.py
    main.py                 # FastAPI app entry
    config.py               # load env vars / base config
    db.py                   # SQLAlchemy setup, session
    models.py               # SQLAlchemy models
    schemas.py              # Pydantic schemas
    routers/
      projects.py
      scans.py
      events.py
      settings.py
    services/
      scanner/
        __init__.py
        orchestrator.py     # run_scan logic
        subdomains.py
        dns_monitor.py
        http_monitor.py
        shodan_monitor.py
        endpoints.py
        takeover.py
      notifiers/
        __init__.py
        base.py
        slack.py
        discord.py
        telegram.py
      diff/
        __init__.py
        subdomains.py
        dns.py
        http.py
        shodan.py
        endpoints.py
    utils/
      cli_tools.py          # subprocess wrappers for subfinder, dnsx, httpx, etc.
      time_utils.py
  web/
    templates/              # Jinja2 templates
    static/                 # CSS/JS
  cli.py                    # Optional CLI entrypoint to run scans via command-line
  requirements.txt
  README.md
```

If you think a slightly different structure is better, feel free to adjust, but keep it modular and easy to extend.

---

## 8. Deliverables

1. **Database models and migrations** for SQLite.
2. **FastAPI app** with:

   * CRUD endpoints for projects, domains, settings.
   * Endpoints to trigger scan for a given project and mode.
   * Endpoints to list events, snapshots.
3. **Web UI** using Jinja2 templates (or minimal frontend stack) with:

   * Dashboard.
   * Project detail pages.
   * Config pages.
4. **Scanner services** implemented with subprocess calls to external tools.
5. **Notifier implementations** for Slack, Discord, Telegram.
6. **README** explaining:

   * How to install dependencies.
   * How to configure env variables (Shodan key, webhooks, etc).
   * How to run the web app.
   * How to trigger scans (via CLI & via web).

Please start by:

1. Proposing the final architecture and folder structure.
2. Then generate the actual code files step by step (backend, models, services, web UI).
3. Make sure the code is runnable as-is with `uvicorn app.main:app --reload` after installing requirements.
