# HoneyStrike — Compliance and Legal Self-Audit Checklist

Complete before first production deployment and review annually.  
**Auditor:** _____________  **Date:** _____________

---

## Part A: Legal Authorisation

- [ ] **A1.** I own or have written authorisation to operate a honeypot on the IP address(es) used for this deployment
- [ ] **A2.** The hosting provider (e.g. Hetzner) Terms of Service permit honeypot operations on their network
- [ ] **A3.** I have confirmed with the hosting provider that inbound attack traffic will not result in my account being suspended
- [ ] **A4.** No real services conflict with honeypot ports on this IP (no real SSH on 22, no real HTTP on 80/443)
- [ ] **A5.** I understand that honeypots are passive — this system does not initiate connections to attackers, does not counter-attack, and does not exploit attacker systems
- [ ] **A6.** If deploying in Romania: I have verified compliance with Law 161/2003 on cybercrime (Article 42–48)

---

## Part B: GDPR / Data Protection (EU Operators)

- [ ] **B1.** I have identified the legal basis for processing IP address data (Legitimate Interest — Art. 6(1)(f) GDPR)
- [ ] **B2.** A Legitimate Interest Assessment (LIA) has been completed and documented (see 07_Compliance_and_Legal_Packet.md)
- [ ] **B3.** Data minimisation is applied — only data necessary for threat analysis is captured
- [ ] **B4.** Retention limits are defined and enforced (see 06_Data_Retention_Matrix.md)
- [ ] **B5.** Raw IP data is not published externally in identifiable form (minimum /24 aggregation before any publication)
- [ ] **B6.** No cross-referencing of honeypot IPs with personal data from other systems
- [ ] **B7.** This deployment is recorded as a processing activity in a Records of Processing Activities (RoPA) document
- [ ] **B8.** MaxMind GeoLite2 is used under their EULA (signed up with a legitimate MaxMind account)
- [ ] **B9.** AbuseIPDB usage complies with their Terms of Service (1000 req/day free tier respected via Redis caching)

---

## Part C: Third-Party API Compliance

- [ ] **C1.** MITRE ATT&CK: All generated reports include required CC BY 4.0 attribution (see 07_Compliance_and_Legal_Packet.md, Section 7)
- [ ] **C2.** AbuseIPDB: Not auto-reporting captured IPs (manual operator decision only)
- [ ] **C3.** MaxMind: Account in good standing; GeoLite2 updated at least monthly
- [ ] **C4.** Telegram: Bot created through official @BotFather; no abuse of Telegram API rate limits

---

## Part D: Security Controls

- [ ] **D1.** No attacker-supplied data is executed or evaluated (commands stored as inert strings only)
- [ ] **D2.** All database queries are parameterised (no raw SQL string construction with attacker data)
- [ ] **D3.** Report generator uses Jinja2 autoescaping — attacker data cannot inject HTML/JS into reports
- [ ] **D4.** Payload size limits enforced at capture time (passwords ≤ 256 chars, HTTP body ≤ 64KB, etc.)
- [ ] **D5.** Dashboard requires JWT authentication — no unauthenticated access to session data
- [ ] **D6.** Container security: non-root user, read-only rootfs, capability restrictions applied
- [ ] **D7.** No secrets in git history (verified with `git log --all -S "password" --oneline`)
- [ ] **D8.** Trivy container scan passed: zero CRITICAL CVEs

---

## Part E: Responsible Disclosure

- [ ] **E1.** If captured data reveals a coordinated attack against identifiable third parties, I will report to the relevant ISAC or national CERT (CERT-RO for Romanian targets)
- [ ] **E2.** Any research publications based on HoneyStrike data will anonymise IPs to /24 minimum and not include individual usernames or passwords
- [ ] **E3.** A `SECURITY.md` file exists in the repository describing the responsible disclosure policy for the HoneyStrike codebase itself
- [ ] **E4.** If HoneyStrike software itself has a vulnerability discovered, it will be fixed before public disclosure

---

## Part F: Operational Compliance

- [ ] **F1.** Daily backup routine is running and tested
- [ ] **F2.** Retention crons are running (events archival, report file cleanup)
- [ ] **F3.** Access to the dashboard is restricted to the operator (no shared credentials)
- [ ] **F4.** Audit log (alerts table) captures all operator API actions

---

## Sign-Off

| Section | Status | Notes |
|---------|--------|-------|
| A — Legal Authorisation | PASS / FAIL / N/A | |
| B — GDPR | PASS / FAIL / N/A | |
| C — Third-Party APIs | PASS / FAIL / N/A | |
| D — Security Controls | PASS / FAIL / N/A | |
| E — Responsible Disclosure | PASS / FAIL / N/A | |
| F — Operational | PASS / FAIL / N/A | |

**Overall compliance status:** COMPLIANT / NON-COMPLIANT  
**Next review date:** _____________
