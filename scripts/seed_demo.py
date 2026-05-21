#!/usr/bin/env python3
"""Seed the database with synthetic attacker sessions for a public demo.

A fresh HoneyStrike instance has an empty dashboard, which makes a poor first
impression for a hosted demo. This script inserts a few hundred realistic-
looking sessions (varied services, countries, tools, MITRE TTPs, scores)
spread over the last few days, plus their fingerprints — enough to light up
the live map, the analytics charts, the sessions list, and the war room.

It writes ONLY synthetic data (RFC 5737 / documentation IP ranges, fictional
geo). Safe to run against a demo DB; do not run against a real capture DB.

    python scripts/seed_demo.py --count 250
    DATABASE_URL=... python scripts/seed_demo.py        # default 200
"""

from __future__ import annotations

import argparse
import asyncio
import random
import uuid
from datetime import UTC, datetime, timedelta

from honeystrike.core.db import dispose_engine, session_scope
from honeystrike.core.models import Fingerprint, Session, TTPMatch

# Documentation/example IP blocks (RFC 5737 + RFC 3849-ish) — never real hosts.
_IP_POOLS = ["192.0.2.", "198.51.100.", "203.0.113."]

_GEO = [
    ("RU", "Russia", "Moscow", 55.75, 37.62, 12345, "Example Telecom RU"),
    ("CN", "China", "Beijing", 39.90, 116.40, 4837, "Example Net CN"),
    ("US", "United States", "Ashburn", 39.04, -77.49, 14618, "Example Cloud US"),
    ("BR", "Brazil", "São Paulo", -23.55, -46.63, 28573, "Example ISP BR"),
    ("IN", "India", "Mumbai", 19.08, 72.88, 9829, "Example Broadband IN"),
    ("DE", "Germany", "Frankfurt", 50.11, 8.68, 24940, "Example Hosting DE"),
    ("NL", "Netherlands", "Amsterdam", 52.37, 4.90, 60781, "Example VPS NL"),
    ("VN", "Vietnam", "Hanoi", 21.03, 105.85, 7552, "Example Telecom VN"),
    ("ID", "Indonesia", "Jakarta", -6.21, 106.85, 17974, "Example Net ID"),
    ("KR", "South Korea", "Seoul", 37.57, 126.98, 4766, "Example Telecom KR"),
]

_SERVICES = ["ssh", "http", "ftp", "rdp", "tls", "telnet", "smtp", "redis"]

_TOOLS = ["Hydra", "sqlmap", "Nikto", "Masscan", "Medusa", "Internet-wide scanner"]

# (technique_id, name, tactic)
_TTPS = [
    ("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
    ("T1110.004", "Brute Force: Credential Stuffing", "Credential Access"),
    ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("T1083", "File and Directory Discovery", "Discovery"),
    ("T1595.001", "Active Scanning: Scanning IP Blocks", "Reconnaissance"),
    ("T1592", "Gather Victim Host Information", "Reconnaissance"),
    ("T1078", "Valid Accounts", "Defense Evasion"),
]


def _severity(score: int) -> str:
    if score < 20:
        return "low"
    if score < 50:
        return "medium"
    if score < 80:
        return "high"
    return "critical"


def _rand_ip() -> str:
    return random.choice(_IP_POOLS) + str(random.randint(1, 254))


async def seed(count: int) -> None:
    now = datetime.now(UTC)
    async with session_scope() as db:
        for _ in range(count):
            geo = random.choice(_GEO)
            service = random.choice(_SERVICES)
            # Bias scores so the demo has a believable severity spread.
            score = random.choices(
                [random.randint(0, 19), random.randint(20, 49),
                 random.randint(50, 79), random.randint(80, 100)],
                weights=[35, 30, 20, 15],
            )[0]
            started = now - timedelta(
                days=random.randint(0, 5),
                minutes=random.randint(0, 1440),
            )
            duration = random.randint(80, 60_000)
            n_events = random.randint(1, 25)
            src_ip = _rand_ip()

            sess = Session(
                id=uuid.uuid4(),
                src_ip=src_ip,
                src_port=random.randint(1024, 65535),
                service=service,
                state="CLOSED",
                threat_score=score,
                severity=_severity(score),
                duration_ms=duration,
                event_count=n_events,
                started_at=started,
                ended_at=started + timedelta(milliseconds=duration),
            )
            db.add(sess)
            # Flush so the FK from fingerprints/ttp_matches → sessions resolves
            # (no ORM relationship is declared, so we order the insert ourselves).
            await db.flush()

            tools = []
            if score >= 50 and random.random() < 0.8:
                tools = [{"name": random.choice(_TOOLS),
                          "confidence": round(random.uniform(0.7, 0.97), 2)}]
            db.add(Fingerprint(
                session_id=sess.id,
                ip=src_ip,
                country_iso=geo[0],
                country_name=geo[1],
                city=geo[2],
                lat=geo[3],
                lon=geo[4],
                asn=geo[5],
                org=geo[6],
                abuse_score=random.randint(0, 100) if random.random() < 0.7 else None,
                tool_signatures=tools,
                ja3_hash=uuid.uuid4().hex[:32] if service == "tls" else None,
                timing_pattern=random.choice(["burst", "slow", "random", "unknown"]),
                attempt_rate_rpm=round(random.uniform(1, 600), 2),
                raw_enrichment={"demo": True},
                created_at=started + timedelta(milliseconds=duration + 50),
            ))

            # Attach 0–3 TTPs, more likely on higher scores.
            n_ttps = random.choices([0, 1, 2, 3], weights=[
                40 if score < 50 else 10, 30, 20, 10,
            ])[0]
            for tid, tname, tactic in random.sample(_TTPS, k=min(n_ttps, len(_TTPS))):
                db.add(TTPMatch(
                    session_id=sess.id,
                    technique_id=tid,
                    technique_name=tname,
                    tactic=tactic,
                    confidence=round(random.uniform(0.6, 0.95), 3),
                    trigger_event_id=None,
                    matched_at=started + timedelta(milliseconds=duration + 60),
                ))
        await db.commit()
    print(f"✓ seeded {count} synthetic demo sessions")


async def _main() -> None:
    ap = argparse.ArgumentParser(description="Seed synthetic demo data.")
    ap.add_argument("--count", type=int, default=200, help="number of sessions")
    args = ap.parse_args()
    try:
        await seed(args.count)
    finally:
        await dispose_engine()


if __name__ == "__main__":
    asyncio.run(_main())
