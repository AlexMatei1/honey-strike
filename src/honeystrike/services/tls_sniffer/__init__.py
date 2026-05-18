"""TLS-fingerprint honeypot (Phase 5 stretch).

Accepts TCP connections, reads the first TLS record, computes the JA3
ClientHello fingerprint, persists it as a session + TLS_CLIENT_HELLO event,
then closes the connection with a graceful TLS alert. No real TLS handshake
is performed — the goal is *just* to capture the attacker's TLS-stack
fingerprint, not to terminate the connection plausibly.

Why a standalone listener rather than wiring JA3 into Caddy in front of
the dashboard:
  - JA3 needs the raw ClientHello bytes BEFORE the TLS handshake completes.
    Reverse proxies that terminate TLS (Caddy, nginx, traefik) consume those
    bytes themselves and don't expose them downstream — so the only way to
    capture the fingerprint is to listen on the raw socket directly.
  - Putting that listener in front of Caddy adds a hop on the dashboard's
    hot path, which we don't want.
  - A standalone JA3 honeypot on a high port catches the exact traffic we
    care about: attackers running TLS scanners against random ports.
"""
