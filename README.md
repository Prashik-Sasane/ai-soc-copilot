# AI SOC Copilot

Evidence-grounded SOC investigation workspace. FastAPI backend, Next.js frontend, PostgreSQL/SQLite storage.

The system ingests events through an authenticated webhook or file upload, normalizes them, raises alerts from detection rules, correlates related alerts into incidents, retrieves tenant-isolated knowledge (RAG), maps candidate MITRE ATT&CK techniques, and optionally enriches IOCs with VirusTotal / AlienVault OTX. Copilot recommendations cite stored evidence. Response actions are recommendations until an analyst approves them; this platform does not isolate hosts or reset credentials.

**RAG retrieves knowledge. It does not train or fine-tune a model.** Analyst feedback is stored for review only.

---

## Run with Docker Compose

```bash
cp .env.example .env
# optional: set GEMINI_API_KEY, VT_API_KEY, OTX_API_KEY, LLM_PROVIDER
docker-compose up --build
```

- Frontend: http://localhost:3001
- API: http://localhost:8000/api/v1
- OpenAPI: http://localhost:8000/api/v1/docs

Default logins (change in production):

| Email | Password | Role |
| --- | --- | --- |
| analyst@aisoc.io | AnalystSOC123! | analyst |
| admin@aisoc.io | AdminSOC123! | admin |

Both seeded users share `tenant_default`. Newly registered users get their own tenant.

New public registrations are analyst-only; an admin account must be provisioned by an administrator. New passwords must be at least 12 characters and use at least two character types. The registration page rates passwords as weak, medium, or strong locally in the browser.

After signing in, open **Account Security** in the sidebar to enroll an authenticator app such as Google Authenticator. Scan the QR code, confirm a current six-digit code, then save the one-time recovery codes. Login will require an authenticator or unused recovery code after MFA is enabled. Login attempts are limited by hashed account/IP buckets (10 attempts per 15 minutes); MFA attempts are limited to 5 per 10 minutes. Sign-out revokes all of that user's current JWTs; tokens expire after 60 minutes by default.

The MFA secret is encrypted with a key derived from `SECRET_KEY`. Keep that key stable and set a unique random value of at least 32 characters before production use; production startup rejects the built-in development key. QR rendering uses the `qrcode[pil]` dependency installed from backend requirements.

Set `ENVIRONMENT=production` to disable demo seeding (`/events/seed-demo`, `/events/simulate-scenario`, `/knowledge/seed-playbooks`).

---

## Required environment variables

See `.env.example`. Important keys:

| Variable | Purpose | If missing |
| --- | --- | --- |
| `DATABASE_URL` | PostgreSQL or SQLite | App will not start |
| `SECRET_KEY` | JWT signing | Use a unique value in production |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access-token lifetime | 60 minutes by default; sign-out revokes all active tokens for that user |
| `INGEST_WEBHOOK_TOKENS` | `source_id:token` pairs for webhook ingest | Webhook returns 404/401 |
| `EMBEDDING_PROVIDER` | `mock` (offline hash, labeled) or `gemini` | `gemini` without `GEMINI_API_KEY` errors; no silent semantic fallback |
| `GEMINI_API_KEY` | Semantic embeddings and optional Gemini LLM | Offline hash retrieval / no LLM summary |
| `GEMINI_MODEL` | Gemini model for summaries (must be one your key can access) | Tries the next alias in a fallback chain (`gemini-3.5-flash`, `gemini-flash-latest`) on a retired-model `404`, a transient capacity `503`, an invalid request `400`, or a request `timeout`; if all fail, a template summary is used and `llm_used` stays `false`. Google retires model names over time — list live ones with `GET https://generativelanguage.googleapis.com/v1beta/models` |
| `LLM_PROVIDER` | `mock`, `gemini`, `openai`, `ollama` | Summaries use evidence templates and disclose that no LLM was used |
| `OPENAI_API_KEY` | OpenAI summaries when `LLM_PROVIDER=openai` | LLM not used |
| `VT_API_KEY` / `OTX_API_KEY` | Live IOC enrichment | Lookup status `not_configured`; never shown as clean |
| `TI_CACHE_TTL_MINUTES` | IOC cache expiry | Default 60 |
| `ENABLE_DEMO_SEEDING` | Dev-only simulated scenarios | Forced off when `ENVIRONMENT=production` |

Never put API keys in source, the browser bundle, or logs.

---

## Connect a real data source

Splunk, Elastic, Microsoft Sentinel, and EDR **pollers are not implemented**. Do not configure those products in this repo and expect them to work.

Use the source-agnostic webhook:

```http
POST /api/v1/ingest/webhook/webhook-default
X-Ingest-Token: dev-ingest-token
X-Tenant-Id: tenant_default
Content-Type: application/json
```

Body may be a single object, an array, or `{"events":[...]}`.

Authenticated analysts can also `POST /api/v1/events/ingest` with a JSON/JSONL/CSV file.

**Real source example (Windows host).** `scripts/windows-event-forwarder.ps1` reads genuine local telemetry (Windows Defender + PowerShell operational logs, and the Security log when run elevated) and forwards it to the webhook:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows-event-forwarder.ps1 `
  -BaseUrl http://127.0.0.1:8000/api/v1 -SourceId webhook-default -Token dev-ingest-token
```

Schedule it as a Windows Scheduled Task for near-real-time intake. This is a real data source (your own host) — it does not fabricate events.

If nothing is connected, the UI shows **No source connected / waiting for data**. The product does not invent live alerts.

Header status polls `/api/v1/ingest/status` every five seconds (`last_event_at`, connection state). `GET /api/v1/ingest/stream` is an optional SSE feed for clients that can send a bearer token.

### Event schema (normalized)

| Field | Notes |
| --- | --- |
| `event_id` | Client id; duplicates per tenant are rejected (idempotent) |
| `timestamp` | ISO-8601; future >24h or older than `MAX_EVENT_AGE_DAYS` rejected |
| `source` | `edr`, `firewall`, `identity`, `dns`, `email_gateway`, … |
| `event_type` | e.g. `process_creation`, `network_conn` |
| `severity` | `low` `medium` `high` `critical` |
| `hostname`, `user`, `src_ip`, `dst_ip`, `src_port`, `dst_port` | Entities used for correlation |
| `domain`, `process_name`, `command_line`, `file_hash` | Detection / MITRE evidence |
| `raw_data` | Original text or JSON string |

Common SIEM/EDR aliases (`@timestamp`, `host.name`, `process.command_line`, `source.ip`, …) are flattened into this schema. That is field mapping only, not a vendor integration.

After ingest, detection rules create alerts; the correlation engine groups alerts that share host, user, or IP inside `CORRELATION_WINDOW_MINUTES`. Each alert stores why it was linked.

---

## Knowledge, MITRE, and threat intel

- **Upload** playbooks on Knowledge & Audit (title, source, owner, version, content). Retrieval is tenant-isolated.
- **Sync CISA KEV**: public catalog, stored with source URL and retrieval time; repeatable without duplicate titles.
- **Sync MITRE ATT&CK**: enterprise STIX from mitre-attack; techniques stored with source URL and version. Until sync succeeds, a labeled bundled subset is used.
- **Re-index vectors** after changing `EMBEDDING_PROVIDER`.
- **IOC lookup**: VirusTotal and/or OTX when keys exist. UI shows provider, lookup time, cache expiry, and `unknown` / `not_found` / `provider_unavailable` / `not_configured`.

---

## Local development without Docker

```bash
# backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# frontend
cd frontend
npm install
npm run dev
```

Frontend defaults to `http://localhost:8000/api/v1`. Docker frontend is published on port 3001.

### Tests

```bash
cd backend
pytest tests
```

External APIs are mocked. Real credentials are not required.

```bash
cd frontend
npx tsc --noEmit
```

---

## What remains unavailable until you configure it

| Capability | Status |
| --- | --- |
| Live event flow | Needs webhook or file ingest (or explicit **dev** simulate) |
| Semantic RAG | `EMBEDDING_PROVIDER=gemini` and `GEMINI_API_KEY` |
| LLM narrative summaries | `LLM_PROVIDER` plus matching API key |
| Live IOC reputation | `VT_API_KEY` and/or `OTX_API_KEY` |
| Full ATT&CK catalog | Run **Sync MITRE ATT&CK** |
| Splunk / Elastic / Sentinel / EDR pollers | **Not implemented** |
| Automatic containment | **Not implemented** (approval records only) |
| Model training from feedback | **Not implemented** |

---

## Demo mode (development only)

`Simulate Attack` / `seed-demo` generates **labeled simulated** events and runs the same detect/correlate path. Disabled when `ENVIRONMENT=production`.
