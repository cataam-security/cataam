# HIPAA Security Rule Checklist

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

**Organization:** [COMPANY NAME]  
**Organization Type:** [ ] Covered Entity  [ ] Business Associate  
**Assessment Date:** [DATE]  
**Assessor:** [NAME, TITLE]

**Reference:** 45 CFR Part 164, Subpart C (Security Standards for the Protection of Electronic Protected Health Information)

---

## Overview

The HIPAA Security Rule requires covered entities and business associates to implement administrative, physical, and technical safeguards to protect electronic Protected Health Information (ePHI).

**Safeguard categories:**
- **Administrative Safeguards** — § 164.308 (9 standards)
- **Physical Safeguards** — § 164.310 (4 standards)
- **Technical Safeguards** — § 164.312 (5 standards)
- **Organizational Requirements** — § 164.314

---

## Administrative Safeguards — § 164.308

### § 164.308(a)(1) — Security Management Process (Required)

**Standard:** Implement policies and procedures to prevent, detect, contain, and correct security violations.

| Implementation Specification | R/A | Implemented | Evidence | Notes |
|------------------------------|-----|-------------|----------|-------|
| Risk Analysis | R | [ ] | | Formal risk analysis of ePHI systems |
| Risk Management | R | [ ] | | Risk treatment plan with tracking |
| Sanction Policy | R | [ ] | | Disciplinary policy for security violations |
| Information System Activity Review | R | [ ] | | Audit log review procedures |

### § 164.308(a)(2) — Assigned Security Responsibility (Required)

| Requirement | Implemented | Evidence |
|-------------|-------------|----------|
| Designated security official identified | [ ] | Name: [HIPAA Security Officer] |
| Responsibilities documented | [ ] | Job description / RACI |

### § 164.308(a)(3) — Workforce Security

| Implementation Specification | R/A | Implemented | Evidence |
|------------------------------|-----|-------------|----------|
| Authorization and/or Supervision | A | [ ] | Access provisioning process |
| Workforce Clearance Procedure | A | [ ] | Background check policy |
| Termination Procedures | A | [ ] | Offboarding checklist with ePHI access revocation |

### § 164.308(a)(4) — Information Access Management

| Implementation Specification | R/A | Implemented | Evidence |
|------------------------------|-----|-------------|----------|
| Isolating Healthcare Clearinghouse Functions | R | [ ] | N/A if not a clearinghouse |
| Access Authorization | A | [ ] | Access request and approval records |
| Access Establishment and Modification | A | [ ] | RBAC policy, provisioning tickets |

### § 164.308(a)(5) — Security Awareness and Training

| Implementation Specification | R/A | Implemented | Evidence |
|------------------------------|-----|-------------|----------|
| Security Reminders | A | [ ] | Quarterly security newsletter / alerts |
| Protection from Malicious Software | A | [ ] | Endpoint protection deployment |
| Log-in Monitoring | A | [ ] | Failed login alerting |
| Password Management | A | [ ] | Password policy, manager tool |

**Required:** Annual security awareness training for all workforce members.

- [ ] Training program documented
- [ ] Completion records from current year (target: 100%)
- [ ] Training covers ePHI handling, phishing, incident reporting

### § 164.308(a)(6) — Security Incident Procedures (Required)

| Implementation Specification | R/A | Implemented | Evidence |
|------------------------------|-----|-------------|----------|
| Response and Reporting | R | [ ] | Incident response plan, incident log |

- [ ] Incident response plan covers ePHI breach scenarios
- [ ] Breach notification procedure (HHS within 60 days if > 500 individuals)
- [ ] Small breach log maintained (< 500 individuals, report annually)

### § 164.308(a)(7) — Contingency Plan

| Implementation Specification | R/A | Implemented | Evidence |
|------------------------------|-----|-------------|----------|
| Data Backup Plan | R | [ ] | Backup policy, backup job logs |
| Disaster Recovery Plan | R | [ ] | DR plan document |
| Emergency Mode Operation Plan | R | [ ] | Emergency access procedures |
| Testing and Revision | A | [ ] | Annual DR test results |
| Applications and Data Criticality Analysis | A | [ ] | Business impact analysis |

### § 164.308(a)(8) — Evaluation (Required)

- [ ] Periodic technical and non-technical evaluation of security measures
- [ ] Evaluation triggered by environmental or operational changes
- [ ] Vulnerability scanning results documented
- [ ] Penetration test conducted (recommended annually)

### § 164.308(b) — Business Associate Contracts (Required)

- [ ] BAA in place with all business associates who handle ePHI
- [ ] BAA inventory maintained and reviewed annually
- [ ] BAA template reviewed by legal counsel

---

## Physical Safeguards — § 164.310

### § 164.310(a) — Facility Access Controls

| Implementation Specification | R/A | Implemented | Evidence |
|------------------------------|-----|-------------|----------|
| Contingency Operations | A | [ ] | Emergency facility access procedures |
| Facility Security Plan | A | [ ] | Physical security policy |
| Access Control and Validation Procedures | A | [ ] | Keycard/badge access logs |
| Maintenance Records | A | [ ] | Facility maintenance log |

### § 164.310(b) — Workstation Use (Required)

- [ ] Workstation use policy (defines appropriate use for ePHI access)
- [ ] Screen lock policy (auto-lock within 15 minutes)
- [ ] Clear desk policy for physical ePHI

### § 164.310(c) — Workstation Security (Required)

- [ ] Physical safeguards for workstations accessing ePHI
- [ ] Full-disk encryption on all laptops (FileVault, BitLocker)
- [ ] MDM enrollment for all devices

### § 164.310(d) — Device and Media Controls

| Implementation Specification | R/A | Implemented | Evidence |
|------------------------------|-----|-------------|----------|
| Disposal | R | [ ] | Media destruction policy, certificates |
| Media Re-Use | R | [ ] | Sanitization procedure |
| Accountability | A | [ ] | Hardware asset inventory |
| Data Backup and Storage | A | [ ] | Backup encryption verified |

---

## Technical Safeguards — § 164.312

### § 164.312(a)(1) — Access Control (Required)

| Implementation Specification | R/A | Implemented | Evidence |
|------------------------------|-----|-------------|----------|
| Unique User Identification | R | [ ] | No shared accounts policy, user inventory |
| Emergency Access Procedure | R | [ ] | Break-glass account procedure |
| Automatic Logoff | A | [ ] | Session timeout configuration |
| Encryption and Decryption | A | [ ] | Encryption at rest for ePHI databases |

### § 164.312(b) — Audit Controls (Required)

- [ ] Audit logging enabled on all systems that access ePHI
- [ ] Logs include: user, timestamp, action, resource accessed
- [ ] Log retention minimum: 6 years (HIPAA record retention)
- [ ] Logs reviewed periodically for anomalies
- [ ] Logs protected from modification / deletion

### § 164.312(c) — Integrity

| Implementation Specification | R/A | Implemented | Evidence |
|------------------------------|-----|-------------|----------|
| Mechanism to Authenticate ePHI | A | [ ] | Hash verification, database integrity checks |

### § 164.312(d) — Person or Entity Authentication (Required)

- [ ] Authentication mechanism for all ePHI system access
- [ ] Multi-factor authentication implemented for remote access and privileged accounts
- [ ] Authentication logs retained

### § 164.312(e) — Transmission Security

| Implementation Specification | R/A | Implemented | Evidence |
|------------------------------|-----|-------------|----------|
| Integrity Controls | A | [ ] | TLS with integrity (AEAD ciphers) |
| Encryption | A | [ ] | TLS 1.2+ on all ePHI transmission paths |

- [ ] TLS audit completed — use [`ssl-tls-audit.py`](../tools/ssl-tls-audit.py)
- [ ] No ePHI transmitted over unencrypted channels (email, FTP, HTTP)
- [ ] API endpoints serving ePHI use TLS 1.2+
- [ ] VPN required for remote access to internal ePHI systems

---

## Organizational Requirements — § 164.314

### § 164.314(a) — Business Associate Contracts

- [ ] BAA template reviewed within past 12 months
- [ ] All subcontractors with ePHI access have signed BAAs
- [ ] BAA requires breach notification to covered entity within SLA

---

## Breach Risk Assessment Checklist

When a potential breach occurs, assess the four HITECH factors before determining if notification is required:

| Factor | Question | Assessment |
|--------|---------|-----------|
| Nature of ePHI | What ePHI was involved? | [ ] |
| Who accessed it | Was access by unauthorized person? | [ ] |
| Whether ePHI was acquired | Was ePHI actually viewed / taken? | [ ] |
| Risk mitigation | Was risk mitigated (encryption, return)? | [ ] |

If risk to ePHI is not low after this assessment → breach notification required.

---

## Summary Scorecard

| Safeguard Category | Total Items | Implemented | % Complete |
|-------------------|------------|-------------|-----------|
| Administrative (§ 164.308) | | | |
| Physical (§ 164.310) | | | |
| Technical (§ 164.312) | | | |
| Organizational (§ 164.314) | | | |
| **Total** | | | |

---

*Template maintained by the [Cataam](https://cataam.com) team. MIT License — copy and modify freely.*  
*This template is for informational purposes only and does not constitute legal advice. Consult your legal counsel for HIPAA compliance guidance.*
