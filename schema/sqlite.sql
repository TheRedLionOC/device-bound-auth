-- Tables of the auth module for SQLite / Cloudflare D1 (d1Adapter, or bunSqlAdapter
-- with sqlite://). For D1, put this in a migration (migrations/0001_auth.sql).
--
--  - username is case-insensitive (COLLATE NOCASE): "Admin" and "admin" are the same user.
--  - Timestamps are ms since epoch; active is 0/1.
-- Add the project's own constraints (e.g. CHECK on role) and columns as needed.

CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role          TEXT NOT NULL,
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  deleted_at    INTEGER,
  deleted_by    TEXT
);

CREATE TABLE sessions (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users (id),
  user_agent   TEXT,
  public_key   TEXT,
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  revoked_at   INTEGER
);

CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
