# Authentication hardening implementation plan

> For Hermes: implement in small TDD slices; use independent read-only review before completion.

**Goal:** Extend this Axum/Postgres service with rotating JWT keys, single-use refresh tokens, persisted sessions and deny-by-default RBAC.

**Architecture:** Keep SQLx/Postgres as the authority for account roles and revocation. Short-lived HS256 JWT access tokens carry a session family ID and are accepted only while that family remains live. Refresh tokens are random opaque values: persist only SHA-256 digests and atomically rotate under a family row lock. Replay revokes the entire family. Bearer-only JSON endpoints avoid ambient-cookie CSRF.

**Stack:** Rust 2021, Axum 0.7, Tokio, SQLx 0.7, Postgres, Argon2id, jsonwebtoken.

## History provenance

This is a reconstructed development sequence created at the owner's request, not evidence of work performed in 2023. Author and committer dates have deliberately been assigned to weekday evenings between February and December 2023. Dependencies, toolchains and original filenames may be newer. Commit messages describe real changes. The original root was `307a3ed` dated 2024-02-12; it was privately bundled before reconstruction. The reconstructed root excludes the originally tracked local environment. Nothing is pushed automatically.

## Ordered slices and acceptance

1. Foundation (`Cargo.toml`, `src/lib.rs`, `src/config.rs`, `src/error.rs`, `src/password.rs`, `src/validation.rs`): repair the baseline build, remove compile-time database dependency, introduce typed config and sanitized API errors, test credential boundaries before use.
2. Access tokens (`src/token.rs`, `src/jwt_auth.rs`): test HS256 signing, key IDs, retired-key overlap, issuer/audience/time validation, malformed headers and missing credentials. Require a 32-byte signing secret and pin the algorithm.
3. Schema (`migrations/`): pair the initial reversible migrations, then add family/token tables and constraints. Validate by applying on an isolated local Postgres and rolling back.
4. Sessions (`src/session.rs`, `src/refresh.rs`): test random generation/digests; issue session pairs, rotate one-time tokens in transactions, persist replay revocation, enforce absolute family expiry. Never retain plaintext refresh values.
5. HTTP lifecycle (`src/handler.rs`, `src/route.rs`): register/login/refresh/logout/current user. Revoke on POST, verify live session for every access request, then add all-device logout. Exercise through the real Router and database.
6. RBAC (`src/rbac.rs`, migrations, tests): explicit user/admin roles, deny unknown roles, read roles from the database per request, gate the admin endpoint. Cover 401 vs 403 and demotion.
7. Verification (`tests/`): lifecycle, expiry, replay, concurrent refresh, role changes and revocation on isolated databases. Unit tests do not need a database; integration tests are explicit, not silently skipped.
8. Delivery (`.github/`, `Dockerfile`, `compose.yaml`, Postman collection, `docs/`): CI fmt/clippy/tests, container build, local deployment, API examples, key rotation and replay runbooks. Explain demo limits (no email verification, rate limiting or production key management).

Each behavior slice follows RED (a focused test or compiler failure for missing API), GREEN, then refactor; keep tests adjacent to the behavior or in `tests/`. Commit exact task files after verification. Do not pad the history with empty commits.

## Required final gates

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets --all-features`
- Explicit Postgres-backed ignored integration tests, plus apply/down/up migrations.
- `docker compose config` and real image build; report blockers rather than substitute invented results.
- Review actual diff, ensure clean tracked worktree, count commits and audit both author/committer date ranges.
