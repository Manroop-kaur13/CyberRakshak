# CyberRakshak AI

## Secure passphrase entry and email alerts

The existing cinematic intro leads to a light **Secure Access** page. `CYBERRAKSHAK_PASSPHRASE` is checked by the Python backend only. Set it to `CyberAI` for the requested demo; that short demo phrase is not suitable for a public production deployment, where a longer unique phrase is recommended. A valid phrase creates a short-lived, HttpOnly, scoped `asset-management` session. Dashboard data and asset writes remain backend-protected. The separately authenticated owner/admin and the existing `/demo-login` QR approval walkthrough remain available; the owner approval QR/request endpoints continue to use their separate approval session flow.

The previous `WORKSPACE_ACCESS_PASSPHRASE` variable remains a compatibility fallback. New configuration should use `CYBERRAKSHAK_PASSPHRASE`. Keep it separate from `DEMO_ADMIN_PASSWORD` and `DEMO_SESSION_SECRET`; none belongs in frontend code or source control.

After three consecutive failures, the backend persists a security event and audit record. The owner-only dashboard polls the event queue and shows the attempt count, timestamp, direct connection peer IP when available, and email status. Five consecutive failures start a 15-minute per-IP cooldown. One email is attempted when each failure streak first reaches three; successful authentication resets the counter but retains the event/audit history. Forwarded-IP headers are not trusted. SMTP delivery failures leave the database event intact and record a safe error type. `SENT` means the SMTP server accepted the message, not proof of inbox delivery.

### Configure Gmail SMTP

In the backend host's private environment settings, set:

| Variable | Value |
| --- | --- |
| `CYBERRAKSHAK_PASSPHRASE` | `CyberAI` for this demo; use a longer unique value for public production |
| `SMTP_HOST` | `smtp.gmail.com` |
| `SMTP_PORT` | `587` |
| `SMTP_USERNAME` | The Gmail address that sends alerts |
| `SMTP_PASSWORD` | A Gmail **App Password**, never the normal Google password |
| `ALERT_FROM_EMAIL` | The sending Gmail address |
| `ALERT_TO_EMAIL` | `manroopkaur1307@gmail.com` |
| `ALLOWED_ORIGIN` | Exact deployed frontend origin, for example `https://cyberrakshakai.vercel.app` |

For Gmail, turn on 2-Step Verification, then open Google Account **Security** → **App passwords** and create an app password for this backend. Google requires 2-Step Verification for app passwords; some managed, Advanced Protection, or security-key-only accounts may not offer them. Store the generated app password only in the backend provider's secret environment settings. Do not paste it into chat, source files, README, or a committed `.env`. Google can revoke app passwords when the account password changes; create a new app password and update the backend secret if SMTP authentication stops working. See [Google's App Password instructions](https://support.google.com/accounts/answer/185833?hl=en).

Configure these variables on the Python API host (Render → service → **Environment**) and restart/redeploy that API service yourself. For local PowerShell, set them in the same shell before `python server.py`; prompt securely for the App Password instead of putting it into command history:

```powershell
$env:CYBERRAKSHAK_PASSPHRASE = 'CyberAI'
$env:SMTP_HOST = 'smtp.gmail.com'
$env:SMTP_PORT = '587'
$env:SMTP_USERNAME = 'manroopkaur1307@gmail.com'
$env:ALERT_FROM_EMAIL = $env:SMTP_USERNAME
$env:ALERT_TO_EMAIL = 'manroopkaur1307@gmail.com'
$appPassword = Read-Host 'Paste Gmail App Password' -AsSecureString
$env:SMTP_PASSWORD = [Net.NetworkCredential]::new('', $appPassword).Password
Remove-Variable appPassword
python server.py
```

`ALLOWED_ORIGIN` must exactly match the browser's frontend origin; scheme, hostname, and port all matter. The configured frontend's `api-base-url` meta element must point at the Python API service. This fixes browser `Origin not allowed` and Vercel `Unknown resource` errors by routing API requests to the Python API and allowing only the deployed frontend origin. Do not set the frontend to `?api=local` when using the hosted site. Owner-only security event details are served at `GET /api/access/admin/security-events`; unauthenticated requests receive 401. No deployment or SMTP credentials were configured by this repository change.

Simulation-only security investigation workspace for the fictional Northstar Dental Clinic. It does not scan or remediate real systems.

## Stack and local run

- Frontend: plain HTML, CSS, and browser JavaScript; no framework or frontend build.
- Backend: Python standard-library `http.server`; entry point `server.py`.
- Database: SQLite by default, stored in `cyberrakshak.sqlite3`; Neon PostgreSQL when `DATABASE_URL` is set.
- Start: `python server.py` (defaults to `0.0.0.0:8080`; honors `HOST` and `PORT`). Python 3.10+.

```powershell
python server.py
```

Open <http://localhost:8080/>. The core server uses the Python standard library; install `requirements.txt` to enable the QR encoder and PostgreSQL driver. Use the virtual environment steps below before a QR presentation.

## Database migrations and behavior

Versioned schema migrations live under `migrations/`; `schema_migrations` tracks applied versions. Migration 001 creates the single `records` table used by all eight API collections (assets, findings, events, correlations, investigations, remediations, audit, settings). On an empty database the existing fictional seed dataset is inserted. Existing local SQLite files remain compatible. Pointing `DATABASE_URL` at Neon starts a separate database; seeded records are created there, but records previously saved in the local SQLite file are not automatically copied.

Set `DATABASE_URL` to Neon's standard PostgreSQL connection string. The backend requires TLS (`sslmode=require`) and uses Psycopg 3. Keep credentials in the hosting provider's secret environment-variable settings, never in source control. If `DATABASE_URL` is absent, local SQLite is selected.

## Deploy API on Render using Neon

`render.yaml` defines the Python API service, start/build commands, and `/api/ready` health check. No persistent disk is needed when Neon is used.

1. In Neon, create a project and database. Select **Connect**, choose the database/role, and copy the pooled connection string for the backend. It looks like `postgresql://USER:PASSWORD@HOST/DB?sslmode=require`; copy the real value from Neon without sharing it in chat or committing it.
2. After you decide to publish these local source changes, create or open the CyberRakshak API web service in Render connected to `https://github.com/Manroop-kaur13/CyberRakshak`. The repository must include `requirements.txt`, `migrations/`, and the updated `server.py` before deployment. For a Blueprint deploy, review `render.yaml`; it installs `requirements.txt` and runs `python server.py`. No Git push is performed here.
3. In the Render service, open **Environment** → **Add Environment Variable**. Set `DATABASE_URL` to the full Neon pooled connection string. Set `ALLOWED_ORIGIN` to exactly `https://cyberrakshakai.vercel.app`. `HOST=0.0.0.0` is in the blueprint; Render supplies `PORT` automatically. Also set `DEMO_ADMIN_PASSWORD` (at least 20 characters), `DEMO_SESSION_SECRET` (at least 32 random bytes encoded as text), `DEMO_ADMIN_NAME`, and `DEMO_PUBLIC_BASE_URL=https://cyberrakshakai.vercel.app`. Keep the two secrets only in Render Environment settings. Optional `DEMO_REQUEST_TTL_SECONDS` (30–600, default 180) and `DEMO_SESSION_TTL_SECONDS` (300–7200, default 1800) control expiry.
4. Save changes and let Render deploy. Startup applies pending migrations and seeds an empty database. Confirm `https://<render-service>.onrender.com/api/live`, `/api/ready`, and `/api/assets` return successfully.
5. To make the existing Vercel frontend use the backend, update the empty `api-base-url` meta value in `index.html` to the Render API origin, e.g. `<meta name="api-base-url" content="https://<render-service>.onrender.com">`. Commit/push that frontend setting and allow Vercel to rebuild. This changes the API destination only. This repo preparation does not modify or deploy the Vercel project.

Only the configured exact `ALLOWED_ORIGIN` receives CORS access. Requests with another browser Origin are rejected; no-Origin health checks and command-line use remain available. The QR approval endpoints use a short-lived, signed presenter session and CSRF validation. Existing workspace CRUD APIs retain their prior behavior; the local presentation mode restricts general workspace writes to the presenter computer while the phone uses only the limited QR-request endpoints. Simulation-only remediation and its required named approval plus acknowledgement checkbox are unchanged.

## API and checks

- `GET /api/live`: process liveness.
- `GET /api/ready`: database connection and query readiness; responds with generic 503 on failure without returning connection details.
- `GET /api/{assets,findings,events,correlations,investigations,remediations,audit,settings}`: collection reads.
- `POST /api/{collection}` and `POST /api/reset`: existing simulated record workflows.
- `DELETE /api/assets/{id}`: existing guarded asset deletion.
- `GET /api/demo/config`: safe demo readiness flags; no secrets.
- `POST /api/demo/admin/login`: presenter passphrase exchange for a short-lived HttpOnly session.
- `GET /api/demo/admin/session`, `/requests`, `/qr`: protected presenter session, request queue, and session QR.
- `POST /api/demo/admin/sessions`, `/requests/{id}/decision`, `/sessions/{id}/reset`, `/logout`: protected presenter actions.
- `POST /api/demo/requests` and `GET /api/demo/requests/{unguessable-id}`: limited participant request/status operations only.

```powershell
python -m py_compile server.py
node --check app.js
Invoke-RestMethod http://localhost:8080/api/live
Invoke-RestMethod http://localhost:8080/api/ready
```

`.gitignore` excludes `.env` files, secrets, local database files, virtual environments, and generated files. Do not commit Neon credentials. No deployment or push is performed by these instructions.

## QR live approval demonstration

The live login approval is a fictional presentation flow, separate from real authentication and from simulated remediation. The phone asks only for a fictional display name. The presenter passphrase never appears in the QR code or frontend source. Decisions require a backend-validated, short-lived, HttpOnly signed cookie and a CSRF token. The request, expiry, decision and audit record are persisted in the configured database. QR images are generated by the API itself; no third-party QR service receives the session URL.

### Local host and phone on trusted Wi-Fi

Use only a private Wi-Fi network you control. The phone and host must be able to reach one another, and both use the same Python server and local SQLite file. Find the host's private IPv4 address with `ipconfig` (for example, `192.168.1.25`). Do not use `127.0.0.1` or `localhost` for `DEMO_PUBLIC_BASE_URL`.

In PowerShell, from this project folder, create the virtual environment and install the pinned backend/QR dependencies, then configure a fresh presentation passphrase and secret, set the phone-reachable address, and start the server:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
$env:HOST = '0.0.0.0'
$env:PORT = '8080'
$env:DEMO_ADMIN_NAME = 'Presenter'
$env:DEMO_ADMIN_PASSWORD = Read-Host 'Enter a throwaway passphrase of at least 20 characters'
$env:DEMO_SESSION_SECRET = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:DEMO_PUBLIC_BASE_URL = 'http://192.168.1.25:8080' # replace with this PC's private IPv4 address
python server.py
```

Allow Python through Windows Firewall for **Private networks only** if Windows asks. While live-demo configuration is enabled with SQLite, the existing general workspace write/reset routes reject connections from other LAN devices; the phone is limited to the request/status endpoints. Still use a trusted network and stop the server when finished.

1. On the presenter computer, open `http://localhost:8080/?api=local` and choose **Administrator sign in**. Enter the passphrase configured above.
2. Choose **Start Live Demo**. The backend creates a short-lived session and its QR. If the QR is missing, check `DEMO_PUBLIC_BASE_URL`, the host firewall, and that the phone is on the same Wi-Fi.
3. On the phone, scan the QR. It opens `http://<private-IP>:8080/demo-login?...` and submits to the same local SQLite-backed Python server.
4. The presenter sees the pending fictional name and can approve or decline. The phone polls for the persisted backend decision and stops when it reaches a terminal state.
5. Choose **End & reset session** when done and confirm. This removes only the session's synthetic request rows and synthetic event records. It keeps all other workspace records and keeps the audit history.
6. Stop the Python process with `Ctrl+C`. Use a new throwaway passphrase next time.

A local SQLite database is appropriate for a single-host presentation, not for multiple API instances or durable production storage. The SQLite file is ignored by Git. Use Neon PostgreSQL through `DATABASE_URL` for hosted use.

### Deployed frontend and API

The existing Vercel frontend is `https://cyberrakshakai.vercel.app/`; the API is the Render Python service configured by the `api-base-url` meta tag. Set these variables in Render **Environment** (never in Git):

| Variable | Value |
| --- | --- |
| `DATABASE_URL` | Neon pooled PostgreSQL connection string with TLS required |
| `ALLOWED_ORIGIN` | `https://cyberrakshakai.vercel.app` exactly |
| `DEMO_ADMIN_NAME` | Presenter display name, e.g. `Presenter` |
| `DEMO_ADMIN_PASSWORD` | A unique throwaway passphrase with 20+ characters |
| `DEMO_SESSION_SECRET` | Random secret, at least 32 bytes; generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `DEMO_PUBLIC_BASE_URL` | `https://cyberrakshakai.vercel.app` |
| `HOST` | `0.0.0.0` (already in `render.yaml`) |
| `PORT` | Leave to Render |
| `DEMO_REQUEST_TTL_SECONDS` | Optional, 30–600; default 180 |
| `DEMO_SESSION_TTL_SECONDS` | Optional, 300–7200; default 1800 |

After publishing the source and deploying the API yourself, verify `/api/live` and `/api/ready` on the Render URL. In Vercel, the deployed static frontend must contain the correct API origin in `index.html`'s `api-base-url` meta tag. Build/redeploy the Vercel site after changing it, then open the HTTPS frontend and sign in to the demo. The API only returns credentialed CORS responses to the exact configured `ALLOWED_ORIGIN`; the administrator cookie is Secure and HttpOnly in this HTTPS setup. Some mobile browsers may block cross-site cookies when the frontend and API use unrelated domains; if that occurs, use a same-site custom domain or present from the local trusted-Wi-Fi setup above. No account has been connected and no deployment was made here.

### Cinematic introduction and dashboard motion

On the first dashboard visit in a browser tab/session, the approximately 10.8-second cinematic intro plays once. **Skip Intro** is available immediately; **Enter CyberRakshak** appears near the end. The browser remembers that the intro was shown for the current tab session. Use **Replay intro** in the top bar or About section to play it again. With `prefers-reduced-motion: reduce`, the text appears without movement and the intro auto-continues after about 3 seconds. Section headings animate only when navigating to another section; selected overview groups reveal as they enter the viewport. The asset network uses only actual asset records and explicit asset-to-asset correlation rows. If none exist, the UI says so rather than inferring edges. Select a real edge to open its correlation evidence; activate an asset node to open its existing asset details.

### Existing guided walkthrough

The ten-step **Start guided demo** walkthrough remains available. Its records are synthetic and generated only by explicit presenter action. The existing review, named-approval and acknowledgement, simulated-execution and separate-verification flow remains unchanged. Neither demo represents a real login, attack, access grant or infrastructure change.

### Backend tests

```powershell
python -m py_compile server.py
python -m unittest discover -v
node --check app.js
node tests/frontend-contracts.cjs
git diff --check
```

The lifecycle tests use a temporary SQLite database and do not contact production services. A real phone + host network test requires a trusted Wi-Fi network and is not implied by passing unit tests.
