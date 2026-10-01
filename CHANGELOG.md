# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org): a major version for breaking changes, a minor
version for new options or features, a patch version for fixes.

## 1.0.0 — 2026-10-01

First release, extracted from the wISP ZAMS inventory app.

- Username/password login (PBKDF2-SHA256; each hash stores its iteration count).
- Device-bound sessions: non-extractable ECDSA P-256 key per login, every request signed.
- Session table with immediate revocation, sliding expiration and `session_expired` /
  `session_revoked` 401 codes.
- User administration routes (list, create, update, soft delete, sessions).
- Database adapters: Cloudflare D1 and Bun.SQL (SQLite, PostgreSQL, MySQL), with
  portable SQL and reference tables in `schema/`.
- Login rate limits: Cloudflare Workers binding or in-memory.
- Browser module with no dependencies (Web Crypto + native IndexedDB).
- Every project-specific setting is a `configureAuth()` option.
