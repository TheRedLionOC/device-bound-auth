-- Tables of the auth module for MySQL (reference for projects using the Bun.SQL
-- adapter with mysql://). For SQLite / D1 see sqlite.sql.
-- Tested with MySQL 8.0. Connect with TLS (mysql://...?ssl=require): MySQL 8's default
-- authentication (caching_sha2_password) refuses plain connections from Bun.SQL.
--
-- Differences from SQLite:
--  - username uses a case-insensitive collation (utf8mb4_0900_ai_ci), like SQLite's
--    COLLATE NOCASE ("Admin" = "admin"). It is VARCHAR(100) for the default
--    users.usernameMaxLength (50): deleting a user appends a suffix to free the name
--    (users.deletedUsername, about 30 characters).
--  - Timestamps (ms since epoch) need BIGINT; INT is too small.
--  - active stays INT 0/1 (the queries compare active = 1).
--  - Indexed or unique columns must be VARCHAR (MySQL cannot index TEXT without a length).
-- Add the project's own constraints (e.g. CHECK on role) and columns as needed.

CREATE TABLE users (
  id            VARCHAR(64) PRIMARY KEY,
  username      VARCHAR(100) NOT NULL UNIQUE,
  name          VARCHAR(100) NOT NULL,
  password_hash VARCHAR(100) NOT NULL,
  password_salt VARCHAR(100) NOT NULL,
  role          VARCHAR(30) NOT NULL,
  active        INT NOT NULL DEFAULT 1,
  created_at    BIGINT NOT NULL,
  updated_at    BIGINT NOT NULL,
  deleted_at    BIGINT,
  deleted_by    VARCHAR(64)
) DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

CREATE TABLE sessions (
  id           VARCHAR(64) PRIMARY KEY,
  user_id      VARCHAR(64) NOT NULL,
  user_agent   VARCHAR(300),
  public_key   TEXT,
  created_at   BIGINT NOT NULL,
  last_seen_at BIGINT NOT NULL,
  expires_at   BIGINT NOT NULL,
  revoked_at   BIGINT,
  FOREIGN KEY (user_id) REFERENCES users (id),
  INDEX idx_sessions_user (user_id),
  INDEX idx_sessions_expires_at (expires_at)
) DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;
