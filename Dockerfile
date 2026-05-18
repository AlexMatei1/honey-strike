# =============================================================================
# HoneyStrike — production image
#
# Multi-stage build:
#   1. `builder`  — exports a pinned requirements.txt from Poetry and installs
#                   dependencies into a self-contained virtualenv at /opt/venv.
#   2. `runtime`  — slim image that copies /opt/venv + src/, drops to a non-
#                   privileged user, and exposes the listener entrypoints.
#
# Security hardening (docs/09 §6, docs/19 §2):
#   - Non-root user `honeystrike` (UID 1000)
#   - No build toolchain in the final image
#   - Read-only rootfs is enforced via docker-compose.prod.yml
#   - cap_drop:ALL + cap_add:NET_BIND_SERVICE applied via compose
#
# The same image runs all 4 honeypot services — `command:` in compose
# selects which `python -m honeystrike.services.<svc>` to execute.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — builder
# -----------------------------------------------------------------------------
FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VERSION=2.4.1 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libffi-dev \
        libssl-dev \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install "poetry==${POETRY_VERSION}" \
    && poetry self add poetry-plugin-export

WORKDIR /build
COPY pyproject.toml ./

# Export a lockfile-equivalent requirements.txt (runtime deps only, no dev group).
RUN poetry export --without-hashes --without dev -f requirements.txt -o /tmp/requirements.txt

# Install into a self-contained virtualenv so we can COPY it cleanly into runtime.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# -----------------------------------------------------------------------------
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app/src"

# WeasyPrint (reports) needs these shared libs at runtime; harmless for the
# honeypot listeners. Curl is left in for healthchecks.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        libffi8 \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        fonts-dejavu-core \
        shared-mime-info \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user. UID 1000 matches the host user on most single-operator setups
# so volume mounts (for SSH host keys, reports) work without chown gymnastics.
RUN groupadd --system --gid 1000 honeystrike \
    && useradd --system --uid 1000 --gid 1000 --home /app --shell /bin/false honeystrike

WORKDIR /app

# Copy the prebuilt venv from the builder stage.
COPY --from=builder /opt/venv /opt/venv

# Copy application source. Alembic config + migrations are copied too so the
# same image can run `alembic upgrade head` at deploy time.
COPY --chown=honeystrike:honeystrike src ./src
COPY --chown=honeystrike:honeystrike alembic ./alembic
COPY --chown=honeystrike:honeystrike alembic.ini ./alembic.ini

# Writable runtime dirs (read-only rootfs is enforced at the compose layer).
# A `.keep` sentinel file with the right ownership is required so Docker's
# named-volume init COPIES contents+ownership from the image path on first
# mount. Without it the volume comes up root-owned and the non-root container
# can't write its SSH host key.
RUN install -d -m 0700 -o honeystrike -g honeystrike /var/lib/honeystrike/ssh \
    && touch /var/lib/honeystrike/ssh/.keep \
    && chown honeystrike:honeystrike /var/lib/honeystrike/ssh/.keep \
    && install -d -m 0755 -o honeystrike -g honeystrike /reports /maxmind \
    && touch /reports/.keep /maxmind/.keep \
    && chown honeystrike:honeystrike /reports/.keep /maxmind/.keep

USER honeystrike

# Default command is helpful diagnostic output; compose overrides this per service.
CMD ["python", "-c", "import honeystrike; print('honeystrike', honeystrike.__version__, 'ready')"]
