-- Tables of the auth module for PostgreSQL (reference for projects using the Bun.SQL
-- adapter with postgres://). For SQLite / D1 see sqlite.sql.
-- Tested with PostgreSQL 18.
--
-- Differences from SQLite:
--  - username is CITEXT: case-insensitive like SQLite's COLLATE NOCASE ("Admin" = "admin").
--  - Timestamps (ms since epoch) need BIGINT; INTEGER is too small.
--  - active stays INTEGER 0/1 (the queries compare active = 1), not BOOLEAN.
-- Add the project's own constraints (e.g. CHECK on role) and columns as needed.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
  id            VARCHAR(64) PRIMARY KEY,
  username      CITEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role          TEXT NOT NULL,
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    BIGINT NOT NULL,
  updated_at    BIGINT NOT NULL,
  deleted_at    BIGINT,
  deleted_by    VARCHAR(64)
);

CREATE TABLE sessions (
  id           VARCHAR(64) PRIMARY KEY,
  user_id      VARCHAR(64) NOT NULL REFERENCES users (id),
  user_agent   TEXT,
  public_key   TEXT,
  created_at   BIGINT NOT NULL,
  last_seen_at BIGINT NOT NULL,
  expires_at   BIGINT NOT NULL,
  revoked_at   BIGINT
);

CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
