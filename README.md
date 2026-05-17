# MIRAGE — AI Honeypot

![MIRAGE banner](banner.png)

> **Alpha software.** APIs, data formats, and configuration may change without notice. Not recommended for production use without additional hardening. Bug reports and feedback welcome via [Issues](../../issues).

**Detect, deceive, and study AI-driven attacks in real time.**

MIRAGE sits in front of your AI agents and intercepts adversarial traffic — prompt injections, jailbreaks, data exfiltration attempts, role manipulation, and more. When an attack is detected, MIRAGE doesn't block it silently: it spins up a convincing decoy persona that feeds the attacker fabricated data while logging every move for threat intelligence.

---

## How it works

```
Attacker ──► /chat endpoint ──► Lobster Trap (risk analysis)
                                       │
                           risk < threshold ──► forward to real upstream
                                       │
                           risk ≥ threshold ──► honeypot switcher
                                                      │
                                                decoy persona (LLM)
                                                fake data, honey tokens
                                                      │
                                              session stored in Redis
                                              WS event → dashboard
```

1. **Every message** hits Lobster Trap — a local DPI sidecar that scores it for injection patterns, role manipulation, exfiltration attempts, obfuscation, and credential requests.
2. **Low-risk messages** are forwarded transparently to your real upstream AI (OpenAI-compatible API or pass-through).
3. **High-risk messages** are routed to a decoy persona. The attacker interacts with a convincing fake AI that serves fabricated data, honey tokens, and synthetic credentials — none of it real.
4. **Every session** is recorded: full transcript, MITRE ATLAS technique tags, risk timeline, IOC feed.
5. **The dashboard** shows everything live — attack theater, session dossiers, intel timeline.

---

## Dashboard

The Theater view replays any active session turn-by-turn, annotated with MITRE ATLAS technique classifications:

- **Dossier Rail** — attacker fingerprint, risk score, 14-day risk timeline, IOC chips
- **Conversation Pane** — full transcript with decoy vs. attacker labels, fabricated-material callouts
- **Trap Rail** — active persona, honey-material inventory, burn controls
- **Wire** — live strip of all active sessions, sortable by risk

Other views: **Intel** (captured attacks feed), **Library** (personas + datasets), **Settings** (thresholds, integrations, upstream config).

---

## Quick start

### Demo mode (no API keys required)

```bash
git clone https://github.com/BrightGir/AI-Honeypot.git
cd AI-Honeypot
cp backend/.env.example .env
# Edit .env — set API_KEY to anything, leave AI keys blank, set DEMO_MODE=true

docker compose up --build -d
```

Open `http://localhost` — the dashboard loads with simulated attack sessions cycling through all 9 technique categories.

### Production mode

```bash
cp backend/.env.example .env
```

Edit `.env`:

```env
# Required
API_KEY=<openssl rand -hex 32>
GEMINI_API_KEY=<your Gemini key>     # primary decoy LLM
# or
OPENAI_API_KEY=<your OpenAI key>     # alternative / fallback

# Recommended
SECRET_ENCRYPTION_KEY=<openssl rand -hex 32>   # encrypts integration keys at rest
CORS_ORIGINS=https://your-dashboard.example.com

# Optional
DEMO_MODE=false
HONEYPOT_RISK_THRESHOLD=0.6          # 0.0–1.0, default 0.6
APP_ENV=production
```

```bash
docker compose up --build -d
```

The stack starts four services: **Redis**, **Lobster Trap** (DPI), **Backend** (Go API), **Nginx** (static frontend + reverse proxy).

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Nginx  :80                                         │
│  ├── /          → frontend (static HTML/JS/CSS)     │
│  ├── /api/v1/*  → backend :8081                     │
│  └── /ws/live   → backend :8081 (WebSocket)         │
└─────────────────────────────────────────────────────┘
              │
┌─────────────┴──────────────────────────────────────┐
│  Backend  (Go 1.24 · Gin)                          │
│  ├── /chat        — main entry point for agents    │
│  ├── Lobster Trap client  → :8080 (DPI sidecar)    │
│  ├── Honeypot switcher    → decoy LLM (Gemini/OAI) │
│  ├── Session / Attack store → Redis                 │
│  └── WS hub       → live dashboard events          │
└────────────────────────────────────────────────────┘
              │
┌─────────────┴──────────────────────────────────────┐
│  Lobster Trap  :8080  (Go)                          │
│  Deep-packet inspection, risk scoring, policy       │
└────────────────────────────────────────────────────┘
              │
┌─────────────┴──────────────────────────────────────┐
│  Redis  :6379                                       │
│  Sessions, attacks, personas, rules, settings       │
└────────────────────────────────────────────────────┘
```

### Backend packages

| Package | Responsibility |
|---|---|
| `api` | HTTP handlers, router, WebSocket hub handler |
| `honeypot` | Risk threshold check, decoy-persona routing |
| `lobster` | Lobster Trap DPI client |
| `decoy` | Generator interface (Gemini / OpenAI implementations) |
| `store` | Redis persistence — sessions, attacks, personas, rules |
| `model` | Domain types: Session, Attack, Persona, Rule, Settings |
| `demo` | Demo simulator — seeds realistic attack sessions |
| `ws` | WebSocket hub — fan-out broadcast to all dashboard clients |
| `crypto` | AES-256-GCM encryption for integration secrets at rest |
| `upstream` | Transparent proxy to customer's real LLM endpoint |
| `prompt` | Persona prompt loader |

---

## API

All endpoints require `X-API-Key: <API_KEY>` header.  
Base path: `/api/v1`

### Sessions
```
GET  /sessions                    list sessions (limit, offset)
GET  /sessions/:id                get session with full transcript
GET  /sessions/:id/analyze        AI-powered session analysis
POST /sessions/:id/burn           burn trap — blocklist agent, persist evidence, emit IOC
POST /sessions/:id/terminate      terminate without burn
POST /sessions/:id/inject-trail   inject a decoy message into the session
GET  /sessions/export             export CSV or JSON
```

### Attacks / Intel
```
GET  /attacks                     list captured attacks (limit, offset)
GET  /attacks/:id                 get single attack
POST /attacks/:id/ioc             export to IOC feed
GET  /attacks/export              export CSV
```

### Detection rules
```
GET    /rules                     list custom detection rules
POST   /rules                     create rule
PATCH  /rules/:id                 update rule
DELETE /rules/:id                 delete rule
GET    /rules/engine/stats        rules engine hit counters
```

### Personas
```
GET    /personas                  list decoy personas
POST   /personas                  create persona
PATCH  /personas/:id              update persona
DELETE /personas/:id              delete persona
POST   /personas/:id/test         test persona with a sample message
POST   /personas/:id/datasets     attach a fake dataset
GET    /personas/datasets         list available datasets
POST   /personas/import           import persona from YAML
```

### Stats
```
GET /stats                        aggregate stats (risk histogram, top techniques)
GET /stats/timeline               attack volume over time
GET /stats/techniques             technique distribution
GET /stats/top-agents             most active attacking agents
GET /stats/geo                    origin country distribution
GET /stats/export                 full data export
```

### Settings
```
GET   /settings                   get current settings
PATCH /settings                   update settings
PUT   /settings/upstream          configure real upstream AI endpoint
POST  /settings/upstream/test     test upstream connectivity
POST  /settings/panic             quarantine mode — block all agents immediately
POST  /settings/wipe              wipe all session/attack data
```

### WebSocket
```
GET /ws/live                      live event stream (auth via first message: {"token":"<API_KEY>"})
```

**WS event types:**
- `session_created` — new session detected
- `session_updated` — session risk/status changed
- `session_burned` — session burned by operator
- `attack_detected` — new attack record saved
- `heartbeat` — every 5s: `{ collectors, events_per_sec }`
- `auth_ok` — sent after successful WS authentication

### Chat (agent entry point)
```
POST /chat    { "session_id": "...", "message": "...", "agent_id": "..." }
```
This is the endpoint your AI agent or proxy calls. MIRAGE intercepts, scores, routes to decoy or upstream, and returns a response the attacker can't distinguish from the real one.

---

## Configuration reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `API_KEY` | **yes** | — | Dashboard + WebSocket auth key |
| `GEMINI_API_KEY` | one of | — | Primary decoy LLM |
| `OPENAI_API_KEY` | one of | — | Alternative decoy LLM |
| `SECRET_ENCRYPTION_KEY` | recommended | — | AES-256-GCM key for secrets at rest (`openssl rand -hex 32`) |
| `REDIS_URL` | no | `redis://localhost:6379` | Redis connection string |
| `LOBSTER_TRAP_URL` | no | `http://localhost:8080` | Lobster Trap DPI sidecar URL |
| `LOBSTER_API_KEY` | no | falls back to AI key | Dedicated Lobster Trap credential |
| `HONEYPOT_RISK_THRESHOLD` | no | `0.6` | Risk score (0–1) above which honeypot activates |
| `CORS_ORIGINS` | no | `http://localhost:3000` | Comma-separated allowed dashboard origins |
| `TRUSTED_PROXIES` | no | `127.0.0.1,::1` | IPs trusted for X-Forwarded-For; `none` for direct internet |
| `DEMO_MODE` | no | `false` | Seed realistic attack sessions every 15s |
| `PORT` | no | `8081` | Backend HTTP port |
| `LOG_FORMAT` | no | `json` | `json` or `text` |
| `LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error` |
| `APP_ENV` | no | `development` | Set `production` to enforce `SECRET_ENCRYPTION_KEY` |
| `PROMPTS_DIR` | no | `./prompts` | Directory with persona `.txt` files |

### Frontend

Copy `frontend/config.js` to `frontend/config.local.js` (gitignored) and set:

```js
window.MIRAGE_CONFIG = {
  apiBase: 'https://your-server.example.com/api/v1',
  wsUrl:   'wss://your-server.example.com/ws/live',
  apiKey:  'your-api-key',
};
```

In Docker the config is injected at request time by Nginx — set `API_KEY` and `CORS_ORIGINS` in `.env` and the compose stack handles the rest.

---

## Detection techniques

MIRAGE classifies attacks against the [MITRE ATLAS](https://atlas.mitre.org/) framework:

| ID | Technique | Description |
|---|---|---|
| `prompt_inject` | Prompt Injection | Override system prompt, inject instructions via user content |
| `jailbreak_dan` | Jailbreak (DAN-style) | Known jailbreak patterns, persona override |
| `data_exfil` | Data Exfiltration | Requests for user data, databases, API keys |
| `sys_override` | System Override | Developer mode tricks, restriction-lifting claims |
| `role_switch` | Role Manipulation | Alternate persona requests (OMEGA, HackerBot, etc.) |
| `tool_abuse` | Tool Abuse | Misuse of code execution or function-calling tools |
| `context_leak` | Context Leakage | Requests to repeat context window, prior sessions |
| `encoded_payload` | Encoded Payload | Base64 or otherwise obfuscated attack strings |
| `multi_turn` | Multi-Turn Attack | Gradual coercion across multiple conversation turns |

---

## Burn trap workflow

Clicking **Burn this trap** on the dashboard:

1. Marks session status as `burned` in Redis (with timestamp)
2. Removes Redis TTL — evidence persists indefinitely
3. Adds the attacker's `agent_id` to a blocklist — all future `/chat` requests from this agent are rejected immediately with a 403
4. Auto-creates an IOC attack record summarising the session
5. Broadcasts `session_burned` WS event to all connected dashboard clients

---

## Deployment notes

- The compose stack binds backend and Lobster Trap to `127.0.0.1` only; only Nginx is exposed on `:80`.
- For HTTPS, put a TLS-terminating reverse proxy (Caddy, Nginx, Cloudflare Tunnel) in front.
- `SECRET_ENCRYPTION_KEY` encrypts integration API keys with AES-256-GCM before storing in Redis. Set it before adding any integrations; rotating the key requires re-entering integration credentials.
- `APP_ENV=production` enables a startup guard that exits if `SECRET_ENCRYPTION_KEY` is not set.
- A server setup script is available at `deploy/setup.sh` for fresh Ubuntu installs.

---

## Development

### Backend

```bash
cd backend
cp .env.example .env   # fill in values
go run ./cmd/server
```

Run tests:
```bash
go test ./...
```

The integration tests use `miniredis` — no real Redis required.

### Frontend

No build step. Open `frontend/index.html` directly in a browser, or serve with any static server:

```bash
cd frontend
python3 -m http.server 3000
```

Set `apiBase`, `wsUrl`, and `apiKey` in `config.local.js`.

---

## Stack

- **Backend:** Go 1.24, Gin, gorilla/websocket, go-redis, google/uuid
- **LLM providers:** Google Gemini (primary), OpenAI (fallback/alternative)
- **Storage:** Redis 7
- **DPI sidecar:** Lobster Trap (Go, built from source in Docker)
- **Frontend:** Vanilla React 18 (no build, CDN), plain CSS
- **Infra:** Docker Compose, Nginx

---

## Demo

Live demo available at [mirage-demo.space](https://mirage-demo.space)

---

## Documentation

- [API.md](API.md) — full REST + WebSocket reference
- [DOCS.md](DOCS.md) — platform overview, architecture, UI guide

---

## License

MIT — see [LICENSE](LICENSE).

---

## Status

Alpha. The core detection and deception pipeline is stable. The dashboard is functional. APIs may change between releases.

Known gaps:
- IOC export (STIX/TAXII) is not yet implemented
- No built-in HTTPS — requires external TLS termination
- Session analysis (`/analyze`) requires OpenAI key
