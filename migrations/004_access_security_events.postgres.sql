CREATE TABLE IF NOT EXISTS access_passphrase_failures (
 ip_hash TEXT PRIMARY KEY, failed_count INTEGER NOT NULL, first_failed_at TEXT NOT NULL,
 last_failed_at TEXT NOT NULL, blocked_until TEXT, alert_event_id TEXT
);
CREATE TABLE IF NOT EXISTS access_security_events (
 id TEXT PRIMARY KEY, failed_count INTEGER NOT NULL, occurred_at TEXT NOT NULL,
 source_ip TEXT, source_ip_hash TEXT NOT NULL, blocked_until TEXT,
 email_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED', email_error TEXT, email_sent_at TEXT
);
CREATE INDEX IF NOT EXISTS access_security_events_time_idx ON access_security_events(occurred_at);
CREATE TABLE IF NOT EXISTS workspace_passphrase_sessions (
 id TEXT PRIMARY KEY, identity_id TEXT NOT NULL, permission_scope TEXT NOT NULL CHECK(permission_scope='asset-management'),
 token_hash TEXT NOT NULL UNIQUE, csrf_hash TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS workspace_passphrase_sessions_expiry_idx ON workspace_passphrase_sessions(expires_at);
