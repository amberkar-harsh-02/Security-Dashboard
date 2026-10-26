# Plan: turn Security-Dashboard into a working SIEM

## Where the project is today

- `backend/server.py` is a single Flask file with three routes:
  - `/api/system-health` reads CPU, RAM and disk with psutil.
  - `/api/login` is a fake endpoint that sleeps and fails 10% of the time.
  - `/api/monitor-stats` returns in-memory counters for that fake endpoint.
- Nothing is stored. Restarting the server loses everything.
- There is no log ingestion, no parsing, no detection rules, no alerts and no search. Those are the core of a SIEM.
- There is no `requirements.txt`, and the server runs with `debug=True` and open CORS.
- `frontend/src/App.js` is one component with inline styles. It polls two endpoints every second and draws one CPU line chart.
- The frontend runs on Create React App (`react-scripts` 5), which is deprecated and has known friction with React 19.
- The UI uses emoji headings, generic rounded stat cards and rainbow icon colors. These make it look generated.

## Target architecture

```
 log sources                    backend (Flask)                         frontend (React + Vite)
 ───────────                    ─────────────────────────────────────   ───────────────────────
 Syslog UDP :5514  ─┐
 HTTP POST /ingest ─┼─▶ parsers ─▶ normalized event ─▶ SQLite (events, FTS5)
 Host agent (psutil)┤                     │                              Overview
 Attack simulator  ─┘                     ▼                              Alert queue + detail
                                 detection engine (YAML rules)           Event search
                                          │                              Rules
                                          ▼                              Sources & health
                                 alerts table ─▶ SSE /api/stream ──────▶ live updates
```

## Backend work

### 1. Project hygiene
- Add `backend/requirements.txt` (flask, flask-cors, psutil, pyyaml, pytest).
- Split `server.py` into modules: `app.py`, `db.py`, `ingest/`, `parsers/`, `detection/`, `api/`, `simulator.py`.
- Read config from env vars: port, DB path, CORS origin, debug flag. Default `debug=False`.
- Restrict CORS to the frontend origin.

### 2. Event schema and storage
- Use SQLite from the standard library. No extra database server is needed.
- `events` table with a normalized schema, close to a small subset of Elastic Common Schema:
  `id, ts, ingested_at, source, host, category, action, outcome, severity, user, src_ip, src_port, dst_ip, dst_port, process, message, raw`.
- Add indexes on `ts`, `src_ip`, `user`, `category`.
- Add an FTS5 virtual table on `message` and `raw` for free-text search.
- Add a retention job that deletes events older than N days (default 7).

### 3. Ingestion
- `POST /api/ingest`: accepts one event or a batch as JSON. Protect it with an API key header.
- Syslog listener: a UDP socket on port 5514 in a background thread. Parse RFC 3164 and RFC 5424 lines.
- Parsers for common formats:
  - Linux `sshd` auth lines (failed or accepted password, invalid user).
  - Apache/Nginx combined access logs.
  - Windows security events sent as JSON (4624 logon, 4625 failed logon, 4672 special privileges, 4720 user created).
  - Fallback: keep the raw line with `category=unknown`.
- Host agent: a thread that uses psutil to record new processes, new listening ports and outbound connections on this machine. This gives real local data.
- Existing system health metrics stay, but they become a "sources & health" metric, not the main page.

### 4. Attack simulator (replaces "Generate Traffic")
- Generates realistic event streams for named scenarios, so the dashboard has meaningful data in a demo:
  - SSH brute force from one IP, then a successful login.
  - Password spray: one IP, many usernames.
  - Port scan: one IP touching many destination ports.
  - Web attack: SQL injection and path traversal patterns in access logs.
  - Privilege escalation: new admin user created after a login.
  - Login from a known-bad IP (threat intel match).
- Background noise generator for normal traffic, so detections must find signal in noise.
- `POST /api/simulate/{scenario}` triggers one scenario. The UI exposes this in a "Run scenario" menu.
- The old `/api/login` fake endpoint moves to `/api/demo/login` and logs each request as a real event.

### 5. Detection engine
- Rules live in `backend/rules/*.yml`. Each rule has `id, name, severity, enabled, type, query, window, threshold, group_by, mitre`.
- Rule types:
  - `match`: a single event matches field conditions (example: path contains `../`).
  - `threshold`: count of matching events per `group_by` within `window` is over `threshold` (example: 5 failed logins per `src_ip` in 60 s).
  - `distinct`: count of distinct values (example: more than 20 distinct `dst_port` per `src_ip` in 30 s).
  - `sequence`: event A followed by event B for the same key within the window (example: failed logins then success).
  - `ioc`: field value is in a threat intel list (`backend/intel/bad_ips.txt`).
- The engine evaluates on each ingest batch, with sliding windows in memory, and backed by SQL queries for a cold start.
- Each rule maps to a MITRE ATT&CK technique ID (for example T1110 Brute Force).
- Unit tests with pytest for every rule type, using fixed event fixtures.

### 6. Alerts
- `alerts` table: `id, rule_id, severity, title, status (open, acknowledged, closed), assignee, created_at, updated_at, group_key, event_count, first_seen, last_seen`.
- `alert_events` link table, so each alert shows the events that caused it.
- Deduplication: the same rule and group key within the window updates the existing open alert instead of creating a new one.
- `alert_notes` table for analyst comments.

### 7. API
- `GET /api/events?q=&from=&to=&severity=&src_ip=&user=&page=` for search with pagination.
- `GET /api/alerts`, `GET /api/alerts/{id}` (with linked events and notes), `PATCH /api/alerts/{id}` (status, assignee), `POST /api/alerts/{id}/notes`.
- `GET /api/rules`, `PATCH /api/rules/{id}` (enable or disable).
- `GET /api/stats/overview?range=24h`: alerts per hour by severity, events per minute, top source IPs, top users, top rules.
- `GET /api/sources`: each source with last event time and event rate.
- `GET /api/stream`: Server-Sent Events for new alerts and the live event rate. This replaces the 1-second polling.
- Analyst login for the dashboard: one local account with a hashed password and a signed session cookie.

## Frontend work

### 8. Tooling
- Move from Create React App to Vite. Keep React 19, recharts and lucide-react.
- Add `react-router` for pages.
- Remove CRA leftovers: `App.css`, `logo.svg`, `reportWebVitals.js`.
- One `api.js` module with the base URL from `VITE_API_URL`. No hard-coded `127.0.0.1:5000` in components.
- CSS with custom properties (design tokens) in plain CSS files. No inline style objects.

### 9. Pages
- **Overview**: 24-hour alert timeline, open alert queue (top 10), events-per-minute rate, top source IPs, compact host health.
- **Alerts**: table with filters for status, severity and rule. Bulk acknowledge and close.
- **Alert detail**: rule description and MITRE technique, timeline of linked events, raw log view, notes, status and assignee controls.
- **Event search**: query bar, time range picker, result table with expandable raw rows. Click any IP or user to filter by it.
- **Rules**: list with severity, type, hit count over 24 h, and an enable switch.
- **Sources & health**: each source with last-seen time and rate, plus the existing CPU, RAM and disk metrics.

### 10. Visual direction (so the UI does not look generated)

Subject: a tool a security analyst keeps open for a full shift. Its main job is triage: see what is new, decide fast, drill into evidence. That means dense, calm and readable. It does not need to look like a movie hacker screen.

- **Color** (dark default, with a separate light theme):
  - Base `#1A2029` (blue-gray slate, not pure black), raised surface `#222A35`, lines `#323C4A`.
  - Ink `#E4E8EE`, muted ink `#8D97A6`.
  - Interaction accent `#8FA8FF` (soft periwinkle), used only for focus, links and the selected row.
  - Severity colors are reserved for severity only, and always shown with a text label:
    critical `#E5484D`, high `#F2762E`, medium `#E8B53A`, low `#4C9BE8`, info `#7D8794`.
  - Validate the severity set with the dataviz palette validator for both themes.
- **Type**:
  - IBM Plex Sans for the interface, with tabular numbers for counts and times.
  - IBM Plex Mono only where the data really is machine text: raw log lines, IPs, hashes.
  - Sentence case everywhere. No all-caps labels and no emoji.
- **Layout**:
  - Narrow left rail with icon and text navigation. A top bar holds the global time range and the search field, similar to tools analysts already know.
  - Panels separated by 1px lines and spacing, not a grid of identical shadowed cards.
  - Tables are the main element: 32 px rows, sticky headers, left-aligned text, right-aligned numbers.
  - Small radius (4 px) on controls only.
- **The one memorable element**: a full-width 24-hour alert band at the top of the overview. It is a stacked severity bar per hour that you can brush to set the time range for the whole app.
- **Motion**: only for state changes. A new alert row gets a short highlight. No entrance animations.
- **Quality floor**: keyboard navigation in tables (j/k to move, Enter to open), visible focus, `prefers-reduced-motion`, works down to tablet width, empty states that say what to do (for example "No alerts in this range. Run a scenario to generate test data.").

## Build order

Each phase ends in a working app and one commit.

| Phase | Work | Status |
|---|---|---|
| 1 | Hygiene, module split, requirements, SQLite schema, `POST /api/ingest`, event search API. Tests. | Done (`2799992`) |
| 2 | Parsers, syslog listener, host agent, simulator with noise. | Done (`cefc785`) |
| 3 | Detection engine, rule YAML files, alerts with dedupe. Tests for each rule type. | Done (`265a89e`) |
| 4 | Alert, rule, stats and SSE APIs. Analyst login. | Done (`5c4afa5`) |
| 5 | Vite migration, tokens, app shell, router, API client. | Done (`bb72225`) |
| 6 | Overview and alert band. | Done (`e6f4a0e`) |
| 7 | Alerts list and alert detail. | Done |
| 8 | Event search, rules page, sources page. | Done |
| 9 | Light theme review, accessibility pass, screenshots review, README with setup and demo steps. | Done |

### Status

All nine phases are done. The README describes how to run, use and extend the system.

## Out of scope for now

- Distributed storage (Elasticsearch, ClickHouse). SQLite is enough for a single-host project and keeps setup to `pip install`.
- Full Sigma rule compatibility. The YAML format is Sigma-like and can be extended later.
- Email or Slack notifications. These can follow phase 4 as a small add-on.
