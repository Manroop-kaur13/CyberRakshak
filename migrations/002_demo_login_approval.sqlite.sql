CREATE TABLE IF NOT EXISTS demo_sessions (
 id TEXT PRIMARY KEY, created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('ACTIVE','CLOSED','EXPIRED'))
);
CREATE INDEX IF NOT EXISTS demo_sessions_status_idx ON demo_sessions(status,expires_at);
CREATE TABLE IF NOT EXISTS demo_login_requests (
 id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES demo_sessions(id) ON DELETE CASCADE,
 idempotency_key TEXT NOT NULL, display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 2 AND 48),
 status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','DECLINED','EXPIRED')),
 created_at TEXT NOT NULL, expires_at TEXT NOT NULL, decided_at TEXT, decided_by TEXT, event_id TEXT NOT NULL,
 UNIQUE(session_id,idempotency_key)
);
CREATE INDEX IF NOT EXISTS demo_requests_session_idx ON demo_login_requests(session_id,created_at);
CREATE INDEX IF NOT EXISTS demo_requests_pending_idx ON demo_login_requests(status,expires_at);
CREATE TABLE IF NOT EXISTS demo_admin_sessions (
 id TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL, admin_name TEXT NOT NULL,
 created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS demo_rate_limits (
 id INTEGER PRIMARY KEY AUTOINCREMENT, bucket_key TEXT NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS demo_rate_limits_idx ON demo_rate_limits(bucket_key,action,created_at);
