# CyberRakshak AI

Simulation-only security investigation workspace for the fictional Northstar Dental Clinic. It does not scan or remediate real systems.

## Stack and local run

- Frontend: plain HTML, CSS, and browser JavaScript; no framework or frontend build.
- Backend: Python standard-library `http.server`; entry point `server.py`.
- Database: SQLite by default, stored in `cyberrakshak.sqlite3`; Neon PostgreSQL when `DATABASE_URL` is set.
- Start: `python server.py` (defaults to `0.0.0.0:8080`; honors `HOST` and `PORT`). Python 3.10+.

```powershell
python server.py
```

Open <http://localhost:8080/>. Local SQLite requires no dependencies. PostgreSQL support installs from `requirements.txt`.

## Database migrations and behavior

Versioned schema migrations live under `migrations/`; `schema_migrations` tracks applied versions. Migration 001 creates the single `records` table used by all eight API collections (assets, findings, events, correlations, investigations, remediations, audit, settings). On an empty database the existing fictional seed dataset is inserted. Existing local SQLite files remain compatible. Pointing `DATABASE_URL` at Neon starts a separate database; seeded records are created there, but records previously saved in the local SQLite file are not automatically copied.

Set `DATABASE_URL` to Neon's standard PostgreSQL connection string. The backend requires TLS (`sslmode=require`) and uses Psycopg 3. Keep credentials in the hosting provider's secret environment-variable settings, never in source control. If `DATABASE_URL` is absent, local SQLite is selected.

## Deploy API on Render using Neon

`render.yaml` defines the Python API service, start/build commands, and `/api/ready` health check. No persistent disk is needed when Neon is used.

1. In Neon, create a project and database. Select **Connect**, choose the database/role, and copy the pooled connection string for the backend. It looks like `postgresql://USER:PASSWORD@HOST/DB?sslmode=require`; copy the real value from Neon without sharing it in chat or committing it.
2. After you decide to publish these local source changes, create or open the CyberRakshak API web service in Render connected to `https://github.com/Manroop-kaur13/CyberRakshak`. The repository must include `requirements.txt`, `migrations/`, and the updated `server.py` before deployment. For a Blueprint deploy, review `render.yaml`; it installs `requirements.txt` and runs `python server.py`. No Git push is performed here.
3. In the Render service, open **Environment** → **Add Environment Variable**. Set `DATABASE_URL` to the full Neon pooled connection string. Set `ALLOWED_ORIGIN` to exactly `https://cyberrakshak-ecru.vercel.app`. `HOST=0.0.0.0` is in the blueprint; Render supplies `PORT` automatically. There are no other required secrets.
4. Save changes and let Render deploy. Startup applies pending migrations and seeds an empty database. Confirm `https://<render-service>.onrender.com/api/live`, `/api/ready`, and `/api/assets` return successfully.
5. To make the existing Vercel frontend use the backend, update the empty `api-base-url` meta value in `index.html` to the Render API origin, e.g. `<meta name="api-base-url" content="https://<render-service>.onrender.com">`. Commit/push that frontend setting and allow Vercel to rebuild. This changes the API destination only. This repo preparation does not modify or deploy the Vercel project.

Only the configured exact `ALLOWED_ORIGIN` receives CORS access. Requests with another browser Origin are rejected; no-Origin health checks and command-line use remain available. CORS is not authentication: the existing API write/delete/reset routes are unauthenticated. Restrict access to trusted demo users until authentication is added. Simulation-only remediation and its required named approval plus acknowledgement checkbox are unchanged.

## API and checks

- `GET /api/live`: process liveness.
- `GET /api/ready`: database connection and query readiness; responds with generic 503 on failure without returning connection details.
- `GET /api/{assets,findings,events,correlations,investigations,remediations,audit,settings}`: collection reads.
- `POST /api/{collection}` and `POST /api/reset`: existing simulated record workflows.
- `DELETE /api/assets/{id}`: existing guarded asset deletion.

```powershell
python -m py_compile server.py
node --check app.js
Invoke-RestMethod http://localhost:8080/api/live
Invoke-RestMethod http://localhost:8080/api/ready
```

`.gitignore` excludes `.env` files, secrets, local database files, virtual environments, and generated files. Do not commit Neon credentials. No deployment or push is performed by these instructions.
