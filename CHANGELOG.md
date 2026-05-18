# Changelog

All notable changes to this project will be documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses Conventional Commits.

## [Unreleased]

### Added — Phase 1 Foundation

- Project scaffold (`pyproject.toml`, Poetry, Python 3.13).
- `docker-compose.dev.yml` with Postgres 16 + Redis 7 services.
- `.env.example` documenting every runtime variable.
- Alembic configuration and `001_initial` migration covering all production tables (`sessions`, `events`, `fingerprints`, `ttp_matches`, `reports`, `alerts`, `geo_cache`, `ml_anomaly_scores`) plus new `users` table for dashboard authentication.
- `src/honeystrike/core/events.py` with `EventEnvelope`, `AttackEvent`, `EventType`, `Service` dataclasses mirroring `docs/03_Domain_Events.md`.
- `src/honeystrike/config.py` typed settings (pydantic-settings).
- Pre-commit hooks (`ruff`, `black`, `mypy --strict`, `bandit`).
- GitHub Actions CI: lint + type check + tests against live Postgres/Redis service containers + dependency audit.
- `SECURITY.md`, `README.md`, this `CHANGELOG.md`, `.gitignore`.

### Fixed (docs)

- `docs/04_PostgreSQL_Schema.sql`: added missing `users` table for dashboard auth.
- `docs/04_PostgreSQL_Schema.sql`: made `reports.file_path` nullable (matches retention policy in doc 06 that nulls the column after expiry).
- `docs/05_Indexes_and_Partitioning.sql`: replaced the non-immutable `WHERE expires_at < NOW()` partial index with a plain index on `expires_at` (the original could not be created on PostgreSQL).
