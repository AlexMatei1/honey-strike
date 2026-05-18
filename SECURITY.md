# Security Policy

## Reporting a Vulnerability

If you discover a vulnerability in the HoneyStrike codebase itself (**not** an attack captured by a honeypot deployment), please report it privately rather than opening a public issue.

- **Contact:** open a GitHub Security Advisory on this repository, or email the maintainer.
- **Response target:** acknowledgement within 5 business days; triage within 14 days.

Please include:

- Affected component / file path
- Reproduction steps or proof of concept
- Impact assessment

We will coordinate a fix and a public advisory once a patch is available.

## Supported Versions

Pre-`v1.0` (alpha): only the latest tagged release is supported.

## Scope

In scope:

- HoneyStrike source code (`src/honeystrike`, `services/`, `workers/`, `api/`, `reports/`)
- Default Docker Compose configurations (`docker-compose.*.yml`)
- Documented runbooks and migration scripts

Out of scope:

- Attacker data captured by deployed instances (those are *intentional* attack inputs — they are stored as inert data and are not bugs)
- Third-party dependencies — please report upstream
- Issues that require an attacker already having SSH access to the operator's VPS

## Known acceptable risks

- The honeypot services intentionally accept connections from the public internet. They store attacker-supplied data; this is the product, not a vulnerability.

## Threat model summary

See `docs/07_Compliance_and_Legal_Packet.md` and `docs/08_Capture_Flows_and_Privacy.md` for the full data-flow and sanitisation model.
