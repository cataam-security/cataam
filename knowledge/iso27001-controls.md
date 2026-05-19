# ISO 27001:2022 Annex A — Implementation Guide

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

**Standard:** ISO/IEC 27001:2022 (replaces 2013 edition)  
**Annex A Controls:** 93 controls across 4 themes

This guide provides implementation notes and common pitfalls for each Annex A theme. It is not a substitute for reading the standard — it is the practitioner layer on top of it.

---

## Overview of ISO 27001:2022 Structure

ISO 27001:2022 reorganized from 14 control domains (2013) into **4 themes**:

| Theme | Controls | Scope |
|-------|----------|-------|
| 5 — Organizational Controls | 37 | Policies, roles, supplier relationships, incident management |
| 6 — People Controls | 8 | HR security, training, disciplinary process |
| 7 — Physical Controls | 14 | Physical access, clear desk, equipment security |
| 8 — Technological Controls | 34 | Access control, cryptography, network security, vulnerability management |

---

## Theme 5: Organizational Controls (A.5)

### A.5.1 — Policies for Information Security

**What it requires:** A documented information security policy, approved by management, communicated to all relevant parties, and reviewed at planned intervals.

**Common pitfall:** Having a policy but no review cadence. Auditors will ask when it was last reviewed and who approved it. Annual review is standard.

**Evidence to collect:** Policy document with version history, management sign-off email or meeting minutes, staff acknowledgement records.

### A.5.7 — Threat Intelligence

**New in 2022.** Requires the organization to collect and analyze information about threats to information security.

**Practical implementation:** Subscribe to CISA alerts, NVD, and a threat intelligence feed (free options: AlienVault OTX, Abuse.ch). Document that you review them and act on relevant findings.

### A.5.23 — Information Security for Use of Cloud Services

**New in 2022.** Explicitly requires policies for cloud service acquisition, use, management, and exit.

**Evidence to collect:** Cloud usage policy, vendor risk assessments for AWS/GCP/Azure, data classification applied to cloud-stored data.

---

## Theme 8: Technological Controls (A.8)

### A.8.2 — Privileged Access Rights

**What it requires:** Allocation and use of privileged access rights to be restricted and managed.

**Practical implementation:**
- Document all privileged accounts (service accounts, admin accounts, root)
- Review quarterly — remove accounts no longer needed
- Use just-in-time access where possible (AWS IAM, Azure PIM)
- Require MFA for all privileged access

**Evidence:** Privileged account inventory, quarterly review records, MFA enforcement policy.

### A.8.8 — Management of Technical Vulnerabilities

**What it requires:** Information about technical vulnerabilities of systems in use to be obtained, the organization's exposure to such vulnerabilities evaluated, and appropriate measures taken.

**Practical implementation:**
- Define a vulnerability management policy with SLA: Critical → 24h, High → 7d, Medium → 30d
- Use automated scanning (OpenVAS, Trivy for containers, AWS Inspector)
- Track remediation in a ticketing system (Jira, Linear)
- Use [`cve-scanner.py`](../tools/cve-scanner.py) for product-specific CVE tracking

**Evidence:** Scan reports with timestamps, remediation tickets with closure dates, exception register for accepted risks.

### A.8.9 — Configuration Management

**What it requires:** Configurations, including security configurations, of hardware, software, services, and networks to be established, documented, implemented, monitored, and reviewed.

**Practical implementation:**
- Define a secure baseline configuration for each system type (use CIS Benchmarks)
- Enforce via IaC (Terraform, Ansible, AWS Config)
- Detect drift with configuration management tools or [`env-hardener.sh`](../tools/env-hardener.sh)

### A.8.20 — Networks Security

**What it requires:** Networks and network devices to be secured, managed, and controlled to protect information in systems and applications.

**Practical implementation:**
- Network segmentation by data classification (PCI data separate from corporate)
- Firewall rules documented and reviewed quarterly
- TLS 1.2+ on all internal and external services — use [`ssl-tls-audit.py`](../tools/ssl-tls-audit.py) to verify
- Disable unused ports and protocols

### A.8.24 — Use of Cryptography

**What it requires:** Rules for the effective use of cryptography, including cryptographic key management, to be defined and implemented.

**Key requirements:**
- TLS 1.2 minimum (TLS 1.3 preferred)
- Certificates: 2048-bit RSA or 256-bit ECDSA minimum
- Data at rest: AES-256
- No MD5 or SHA-1 for integrity checks
- Key rotation policy documented

### A.8.25 — Secure Development Life Cycle

**New in 2022 (previously scattered across A.12/A.14).** Rules for the secure development of software and systems to be established and applied.

**Minimum viable program:**
- Threat modeling for new features
- SAST/DAST in CI pipeline (Semgrep, Snyk, OWASP ZAP)
- Dependency scanning (Dependabot, npm audit)
- Code review requirements (no self-merge on main)
- Security training for developers (annual minimum)

---

## Statement of Applicability (SoA)

The SoA is the document that declares which Annex A controls are applicable to your ISMS, which are implemented, and which are excluded (with justification).

**Template row format:**

| Control | Title | Applicable? | Implemented? | Justification / Evidence Reference |
|---------|-------|------------|-------------|-----------------------------------|
| A.8.8 | Management of Technical Vulnerabilities | Yes | Yes | Vulnerability management policy v1.2; Trivy scan results in Jira |
| A.7.4 | Physical Security Monitoring | No | N/A | 100% remote organization; no physical offices |

---

## Certification Audit Tips

1. **Gap assessment first** — before engaging a certification body, do an internal gap assessment against all 93 controls. Fix critical gaps before the Stage 1 audit.
2. **Stage 1 is document review** — your ISMS documentation (policies, risk register, SoA, procedures) must be complete before Stage 1.
3. **Stage 2 is evidence** — auditors will sample controls and ask for evidence. Automate evidence collection where possible.
4. **Risk register is central** — every control in the SoA should trace back to a risk. Auditors look for this linkage.
5. **Management review matters** — ISO 27001 requires periodic management review of the ISMS. Document it (minutes, attendees, decisions).

---

*Maintained by the [Cataam](https://cataam.com) team. For GRC automation and continuous compliance monitoring, visit [cataam.com](https://cataam.com).*
