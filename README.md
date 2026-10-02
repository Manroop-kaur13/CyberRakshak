# CyberRakshak AI

A responsive, simulation-only security investigation workspace for the fictional Northstar Dental Clinic. This project contains no real scanning or device remediation.

## Project structure

- **Frontend:** Plain HTML, CSS, and browser JavaScript (`index.html`, `style.css`, `app.js`). There is no frontend framework, package manager, or compilation step.
- **Backend:** Python 3 standard-library `http.server` application (`server.py`). It serves the frontend and implements the JSON API in the same long-running process.
- **Database:** SQLite, created beside `server.py` as `cyberrakshak.sqlite3`; tables and fictional seed data are initialized by the server. The database is local runtime state and is excluded from Git.
- **Start command:** `python server.py` (default bind `0.0.0.0:8080`; set `PORT` and optionally `HOST` to override).

## Run locally

Requires Python 3.10 or later. No packages need to be installed.

From this directory:

```powershell
python server.py
```

Open <http://localhost:8080/>. The SQLite file is created on first launch and is intentionally ignored by Git. To restore the fictional sample records, use **Settings → Reset demo workspace**; the reset is confirmed in the app and recorded in the audit trail.

## API routes

- `GET /api/live` — process liveness; does not query SQLite.
- `GET /api/ready` — checks SQLite readiness.
- `GET /api/{assets,findings,events,correlations,investigations,remediations,audit,settings}` — list persisted records.
- `POST /api/{collection}` — create/update a record and persist an audit entry.
- `DELETE /api/assets/{id}` — delete an asset only when it has no linked finding or event.
- `POST /api/reset` — restore fictional seed data and audit the reset.

## Checks

Run syntax checks from this directory:

```powershell
python -m py_compile server.py
node --check app.js
```

With the server running, check health and the seeded API:

```powershell
Invoke-RestMethod http://localhost:8080/api/live
Invoke-RestMethod http://localhost:8080/api/ready
(Invoke-RestMethod http://localhost:8080/api/assets).Count
```

There is no frontend build command or automated test suite in this project.

## Deployment compatibility

### Vercel

**This exact project cannot be deployed fully and reliably on Vercel as-is.** Vercel supports Python Functions, but those are request handlers, while `server.py` starts a persistent `ThreadingHTTPServer`. Vercel Functions have a read-only filesystem except for temporary `/tmp` storage; local SQLite writes there would be ephemeral and isolated across instances. Vercel explicitly says local SQLite is not supported for durable application writes ([SQLite on Vercel](https://vercel.com/kb/guide/is-sqlite-supported-in-vercel), [Vercel runtimes](https://vercel.com/docs/functions/runtimes), [Python runtime](https://vercel.com/docs/functions/runtimes/python)).

The frontend files are static and can be served by Vercel, but the current browser code calls relative `/api/...` routes. A static Vercel deployment would not provide this Python API, so the workspace would fail to load. Deploying just the files there is suitable only for a static mock/preview, not the working application.

### Smallest reliable deployment change

The smallest architecture change is to keep this Python server and run it as **one persistent Python web service**, while placing its SQLite file on durable storage. For example, Render supports Python web services and persistent disks; its disk is single-instance and requires a paid service plan ([Render web services](https://render.com/docs/web-services), [Render persistent disks](https://render.com/docs/disks)). Before deploying there, make the database path configurable (for example, `DATABASE_PATH=/var/data/cyberrakshak.sqlite3`) and attach the disk at `/var/data`. The current source hardcodes the database beside `server.py`, so that path change is required; without it, a platform’s ephemeral filesystem can lose database writes on restart or deploy. Use `python server.py` as the start command and configure the platform’s port variable.

To keep the frontend on Vercel, additionally make the frontend API base URL configurable and point it at the API service URL. Configure the API’s allowed browser origin for the Vercel domain. The current API uses a wildcard CORS header and has unauthenticated write and reset routes; before exposing those routes publicly, add appropriate access protection or restrict the service to a controlled demo. CORS alone is not authentication.

For a larger change, convert the API to Vercel Function handlers and move the database to managed remote storage such as Postgres. That requires an API/runtime refactor and persistence migration; Vercel’s Marketplace lists managed database integrations ([Vercel Storage](https://vercel.com/docs/storage)).

### Render deployment outline (after the database-path change)

1. Create a Render **Web Service** from this repository, using this directory as its root.
2. Select Python. There is no dependency installation; use an empty build command or `python -m py_compile server.py` as a syntax-only build command.
3. Set the start command to `python server.py`.
4. Attach a persistent disk mounted at `/var/data`, and set `DATABASE_PATH=/var/data/cyberrakshak.sqlite3` after adding support for that setting in `server.py`.
5. Keep a single service instance while using SQLite. Verify `/api/live`, `/api/ready`, record persistence across a restart, and the public UI before sharing the service URL.

This project has not been deployed to Render or Vercel. No public URL is available yet.

## GitHub setup

After creating an empty GitHub repository, replace `<owner>` and `<new-repository>` and run:

```powershell
git remote add origin https://github.com/<owner>/<new-repository>.git
git push -u origin main
```

Do not commit `.env` files, secrets, local SQLite databases, Python environments, or generated build/cache files; `.gitignore` excludes them.
