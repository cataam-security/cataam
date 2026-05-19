# SOC 2 Type II Evidence Checklist

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

**Organization:** [COMPANY NAME]  
**Audit Period:** [START DATE] to [END DATE]  
**Trust Service Criteria:** [CC / A / C / PI / P — select applicable]  
**Auditor:** [FIRM NAME]

This checklist organizes evidence by Common Criteria (CC) category. Work through each section before your audit kickoff call.

---

## CC1 — Control Environment

### CC1.1 — COSO Principles: Commitment to Integrity and Ethics

- [ ] Code of conduct / ethics policy (signed by all employees)
- [ ] Employee onboarding documentation confirming ethics training
- [ ] Background check policy and evidence of completion

### CC1.2 — Board Oversight of Internal Controls

- [ ] Organization chart showing security governance structure
- [ ] CISO / security function reporting lines
- [ ] Board or executive meeting minutes referencing security oversight (if applicable)

### CC1.3 — Management Structure and Assignments

- [ ] Defined security roles and responsibilities (RACI matrix or job descriptions)
- [ ] Security committee or steering group charter

### CC1.4 — HR Commitment to Competence

- [ ] Security training completion records (annual minimum)
- [ ] Security awareness program documentation
- [ ] Role-specific security training evidence (e.g., developer secure coding training)

### CC1.5 — Accountability for Internal Controls

- [ ] Performance review process that includes security responsibilities
- [ ] Disciplinary process documentation

---

## CC2 — Communication and Information

### CC2.1 — Internal Communication

- [ ] Information security policy (distributed to all staff, dated)
- [ ] Evidence of policy communication (email, intranet confirmation, etc.)
- [ ] Acceptable use policy

### CC2.2 — External Communication

- [ ] Privacy policy (publicly posted)
- [ ] Security contact / responsible disclosure policy
- [ ] Data processing agreements (DPAs) with key customers

### CC2.3 — Reporting to External Parties

- [ ] Incident notification procedure (SLA for notifying customers of breaches)
- [ ] Sample incident notification if any occurred during audit period

---

## CC3 — Risk Assessment

### CC3.1 — Risk Assessment Process

- [ ] Risk assessment methodology document
- [ ] Current risk register (dated within audit period)
- [ ] Evidence of risk register review (meeting minutes, email)

### CC3.2 — Risk Identification

- [ ] Threat and vulnerability register
- [ ] Asset inventory linked to risk register

### CC3.3 — Risk Analysis

- [ ] Risk scoring methodology (likelihood × impact or equivalent)
- [ ] Risk treatment decisions documented

---

## CC4 — Monitoring Activities

### CC4.1 — Control Monitoring

- [ ] Internal audit or control testing schedule
- [ ] Control testing results from audit period
- [ ] Management review meeting minutes (security topics)

### CC4.2 — Evaluation and Communication of Deficiencies

- [ ] Deficiency tracking log (issues found during monitoring)
- [ ] Evidence of remediation for prior audit findings

---

## CC5 — Control Activities

### CC5.1 — Control Selection

- [ ] Information security policy (covers access control, encryption, incident response)
- [ ] Change management policy

### CC5.2 — Technology General Controls

- [ ] Logical access policy
- [ ] Change management tickets from audit period (sample)
- [ ] Deployment pipeline documentation (code review, approval gates)

### CC5.3 — Technology Deployment Controls

- [ ] SDLC policy with security requirements
- [ ] Code review records (PR approval logs from GitHub/GitLab)
- [ ] Static analysis / SAST scan results from audit period

---

## CC6 — Logical and Physical Access Controls

### CC6.1 — Logical Access

- [ ] Access control policy
- [ ] List of all privileged accounts
- [ ] MFA enforcement evidence (screenshot of MFA policy in IdP, e.g. Okta, Azure AD)
- [ ] Unique user ID requirement enforced (no shared accounts)

### CC6.2 — Access Provisioning and Deprovisioning

- [ ] Onboarding / offboarding procedure
- [ ] Access request and approval tickets (sample from audit period)
- [ ] Offboarding evidence: terminated user accounts disabled within SLA
- [ ] Quarterly access review results

### CC6.3 — Role-Based Access

- [ ] RBAC documentation (who has access to what)
- [ ] Principle of least privilege policy
- [ ] Service account inventory

### CC6.6 — Transmission Controls

- [ ] Network security policy
- [ ] TLS configuration evidence — use [`ssl-tls-audit.py`](../tools/ssl-tls-audit.py) output
- [ ] Firewall rules documentation

### CC6.7 — Encryption at Rest and in Transit

- [ ] Encryption policy
- [ ] Evidence of database encryption (RDS encryption enabled, screenshot)
- [ ] Evidence of TLS on all external endpoints
- [ ] S3 bucket encryption configuration

### CC6.8 — Vulnerability and Threat Detection

- [ ] Vulnerability scanning policy (defines frequency and remediation SLAs)
- [ ] Vulnerability scan results from audit period (minimum quarterly)
- [ ] Remediation evidence for Critical/High findings within SLA
- [ ] Penetration test report (if annual pentest is in scope)

---

## CC7 — System Operations

### CC7.1 — Detection and Monitoring

- [ ] Security monitoring / SIEM documentation
- [ ] Alert rule configuration (what events generate alerts)
- [ ] On-call / incident response escalation procedure

### CC7.2 — Security Events

- [ ] Log retention policy (minimum 1 year recommended)
- [ ] Evidence logs are forwarded to central storage
- [ ] Sample log review evidence from audit period

### CC7.3 — Incident Identification

- [ ] Incident classification criteria
- [ ] Incident log from audit period

### CC7.4 — Incident Response

- [ ] Incident response plan (IRP)
- [ ] Evidence IRP was tested or exercised during audit period (tabletop exercise)
- [ ] Post-incident review records (if incidents occurred)

### CC7.5 — Incident Remediation

- [ ] Incident tickets from audit period (showing resolution)
- [ ] Root cause analysis for significant incidents
- [ ] Evidence lessons-learned were applied

---

## CC8 — Change Management

### CC8.1 — Authorized Changes

- [ ] Change management policy
- [ ] Change approval records (sample from audit period)
- [ ] Evidence all production changes went through approved process

---

## CC9 — Risk Mitigation

### CC9.1 — Vendor Risk Management

- [ ] Vendor risk assessment policy
- [ ] Completed vendor assessments for critical/high-risk vendors
- [ ] SOC 2 reports or security questionnaires from subservice organizations

### CC9.2 — Business Continuity

- [ ] BCP / DR plan
- [ ] DR test results from audit period
- [ ] RTO / RPO targets documented and tested

---

## Availability (A) Criteria — if applicable

- [ ] System availability SLA commitments to customers
- [ ] Uptime monitoring tool and SLA performance data from audit period
- [ ] Incident postmortems for any availability incidents
- [ ] Capacity planning documentation

---

## Pre-Audit Checklist

- [ ] All policies reviewed and dated within audit period (or within 12 months prior)
- [ ] All controls have evidence from the **full** audit period (not just recent months)
- [ ] Access review completed and documented
- [ ] Terminated user accounts confirmed disabled
- [ ] Vulnerability scans run and findings tracked
- [ ] Vendor assessments current
- [ ] DR test completed
- [ ] Security training completion ≥ 95% of staff

---

*Template maintained by the [Cataam](https://cataam.com) team. MIT License — copy and modify freely.*
