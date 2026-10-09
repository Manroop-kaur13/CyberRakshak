CREATE TABLE IF NOT EXISTS workspace_access_contexts (
 id TEXT PRIMARY KEY, created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('ACTIVE','CLOSED','EXPIRED'))
);
CREATE INDEX IF NOT EXISTS workspace_access_context_status_idx ON workspace_access_contexts(status,expires_at);
CREATE TABLE IF NOT EXISTS workspace_access_requests (
 id TEXT PRIMARY KEY, context_id TEXT REFERENCES workspace_access_contexts(id), identity_id TEXT NOT NULL,
 proof_hash TEXT NOT NULL, display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 2 AND 48),
 permission_scope TEXT NOT NULL CHECK(permission_scope='asset-management'),
 status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','DECLINED','EXPIRED')),
 created_at TEXT NOT NULL, expires_at TEXT NOT NULL, decided_at TEXT, decided_by TEXT, revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS workspace_access_requests_status_idx ON workspace_access_requests(status,created_at);
CREATE INDEX IF NOT EXISTS workspace_access_requests_identity_idx ON workspace_access_requests(identity_id,created_at);
CREATE TABLE IF NOT EXISTS workspace_access_sessions (
 id TEXT PRIMARY KEY, request_id TEXT NOT NULL REFERENCES workspace_access_requests(id), identity_id TEXT NOT NULL,
 permission_scope TEXT NOT NULL CHECK(permission_scope='asset-management'), token_hash TEXT NOT NULL UNIQUE,
 csrf_hash TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, login_audit_id TEXT
);
CREATE INDEX IF NOT EXISTS workspace_access_sessions_request_idx ON workspace_access_sessions(request_id,expires_at);
