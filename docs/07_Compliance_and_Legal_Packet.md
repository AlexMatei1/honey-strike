# HoneyStrike — Compliance and Legal Packet

> **This document is informational only and does not constitute legal advice. Consult a qualified lawyer in your jurisdiction before deploying.**

---

## 1. Legal Basis for Honeypot Operation

### Is it legal to run a honeypot?

In **most jurisdictions**, operating a honeypot on infrastructure you own or have explicit permission to monitor is legal. The system operator is permitted to:

- Log all incoming connection attempts to services they host
- Record credentials supplied by connecting parties (these are not legitimate credentials)
- Publish aggregated/anonymised threat intelligence derived from the data

### Jurisdiction-specific notes

| Jurisdiction | Status | Key law | Notes |
|-------------|--------|---------|-------|
| Romania | Generally legal | Law 161/2003 (cybercrime) | Operator must own/control the IP space |
| EU (general) | Legal with GDPR controls | GDPR Art. 6(1)(f) | Legitimate interest basis; see Section 3 |
| USA | Legal | CFAA (18 U.S.C. § 1030) | Honeypot must not actively entrap |
| UK | Legal | Computer Misuse Act 1990 | Passive capture is fine; no active exploitation |

---

## 2. What HoneyStrike Does NOT Do

To remain on the right side of computer misuse laws, HoneyStrike must never:

- [ ] Actively probe or scan IP addresses that have connected (no reverse scanning)
- [ ] Exploit vulnerabilities in attacker systems (no counter-hacking)
- [ ] Publish personally identifiable raw IP data without legal basis
- [ ] Intercept data from legitimate users (honeypot ports must not conflict with real services)
- [ ] Impersonate a real organisation's login page (fake admin panel disclaimers recommended in dev/test)

---

## 3. GDPR Compliance Checklist

| Requirement | Status | Notes |
|------------|--------|-------|
| Legal basis identified | ✅ | Art. 6(1)(f) — legitimate interest in security monitoring |
| Data minimisation applied | ✅ | Only capture data relevant to threat analysis |
| Retention limits defined | ✅ | See 06_Data_Retention_Matrix.md |
| Data subject rights | ⚠️ | Attackers technically have rights; in practice, identity unknown |
| Cross-border transfers | ✅ | MaxMind (US) — Standard Contractual Clauses apply |
| AbuseIPDB data sharing | ✅ | Only sending IPs to a third-party abuse database, not PII sets |
| Records of processing | Required | Document this deployment as a processing activity |

### Legitimate Interest Assessment (LIA) Summary

**Purpose:** Detect, log, and analyse hostile network activity targeting operator-controlled infrastructure.

**Necessity:** IP capture, credential logging, and geolocation are the minimum required for meaningful threat intelligence.

**Balancing test:** Connecting entities are initiating unauthorised access attempts. Their expectation of privacy in this context is minimal. The operator's security interest outweighs the privacy interest of credential-stuffing bots.

**Conclusion:** Legitimate interest basis is defensible for this use case under GDPR.

---

## 4. Responsible Disclosure Policy

If HoneyStrike data reveals an active campaign targeting identifiable third parties (e.g. a coordinated attack against a known organisation's IP range):

1. **Do not** contact the targets directly using data obtained from the honeypot
2. Consider submitting IP/TTP data to a coordinated ISAC (Information Sharing and Analysis Center) in the relevant sector
3. If the data suggests imminent serious harm, contact CERT-RO (Romania) or the relevant national CERT
4. If publishing research findings: anonymise all IPs to /24 minimum, aggregate TTPs, remove timestamps that could identify individuals

---

## 5. VPS / Hosting Provider Terms

Before deploying, verify with your hosting provider (e.g. Hetzner) that:

- [ ] Operating honeypot services on their infrastructure is permitted in their ToS
- [ ] You will not be held liable for inbound attack traffic that passes through their network
- [ ] Port 22 conflicts: Hetzner assigns SSH to a different port on new VMs — ensure no conflict with your real management SSH

**Hetzner:** Explicitly permits security research honeypots. Abuse reports for inbound attack traffic are dismissed. Outbound attack traffic is not tolerated — HoneyStrike never initiates outbound connections to attackers.

---

## 6. AbuseIPDB API Usage

By using the AbuseIPDB API, you agree to their Terms of Service, which permit:
- Querying IP reputation for security purposes
- Optionally reporting confirmed malicious IPs (HoneyStrike does not auto-report — this is a manual operator decision)
- Free tier: 1,000 queries/day. Cache responses for 6h minimum to stay within limits.

---

## 7. MITRE ATT&CK Usage

The MITRE ATT&CK framework is published under CC BY 4.0. Usage in HoneyStrike:
- The STIX data bundle is downloaded from the official MITRE GitHub at build time
- TTP mappings in reports must credit: "This product uses the MITRE ATT&CK® framework"
- No endorsement by MITRE is implied

Required attribution in all generated reports:
> *This report uses MITRE ATT&CK® — a globally accessible knowledge base of adversary tactics and techniques. © 2024 The MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation.*
