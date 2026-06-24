# ISO 27001:2022 Risk Assessment Template

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

> **📋 Automate this template.** Generate, score, and maintain your ISO 27001 risk register automatically — with continuous evidence harvesting and a generated Statement of Applicability — using [ISO 27001 compliance automation](https://cataam.com/compliance/iso27001/). The maintained, online version of this template lives at [cataam.com/resources/iso27001-risk-assessment-template](https://cataam.com/resources/iso27001-risk-assessment-template/).

**Organization:** [COMPANY NAME]  
**Assessment Date:** [DATE]  
**Version:** 1.0  
**Owner:** [CISO / Security Manager]  
**Approved by:** [NAME, TITLE]  
**Next Review:** [DATE + 12 months]

---

## 1. Scope

This risk assessment covers the information assets within the scope of the Information Security Management System (ISMS), as defined in the ISMS Scope Document [ref].

**In scope:**
- [List systems, processes, locations, data types]

**Out of scope:**
- [List any explicitly excluded items with justification]

---

## 2. Methodology

### 2.1 Risk Scoring

Risks are scored using a **Likelihood × Impact** matrix on a 1–5 scale.

**Likelihood:**
| Score | Description |
|-------|-------------|
| 1 | Rare — once in 5+ years |
| 2 | Unlikely — once in 2–5 years |
| 3 | Possible — once per year |
| 4 | Likely — multiple times per year |
| 5 | Almost certain — monthly or more |

**Impact:**
| Score | Description |
|-------|-------------|
| 1 | Negligible — no operational impact, no data exposure |
| 2 | Minor — limited impact, quickly resolved |
| 3 | Moderate — significant disruption, limited data exposure |
| 4 | Major — serious harm, regulatory notification likely |
| 5 | Critical — business continuity threatened, mass data breach |

**Risk Score = Likelihood × Impact**

| Score Range | Risk Level | Treatment |
|-------------|-----------|-----------|
| 1–4 | Low | Accept or monitor |
| 5–9 | Medium | Treat within 90 days |
| 10–16 | High | Treat within 30 days |
| 17–25 | Critical | Treat immediately |

### 2.2 Treatment Options

- **Mitigate** — implement controls to reduce likelihood or impact
- **Transfer** — insurance, contractual liability transfer
- **Accept** — document and accept residual risk (requires management sign-off)
- **Avoid** — eliminate the activity that generates the risk

---

## 3. Asset Register

| Asset ID | Asset Name | Type | Owner | Classification | Location |
|----------|-----------|------|-------|----------------|---------|
| A-001 | Customer Database | Data | [Name] | Confidential | AWS us-east-1 |
| A-002 | Production Application | System | [Name] | Restricted | AWS us-east-1 |
| A-003 | Employee HR Records | Data | [Name] | Confidential | [Location] |
| A-004 | Source Code Repository | System | [Name] | Restricted | GitHub |
| A-005 | Payment Processing System | System | [Name] | Restricted | [Location] |
| | | | | | |

---

## 4. Threat and Vulnerability Register

| Threat ID | Threat | Asset(s) | Vulnerability | Existing Controls |
|-----------|--------|----------|---------------|------------------|
| T-001 | Ransomware / malware | A-001, A-002 | Unpatched systems | EDR, patch management |
| T-002 | Phishing / credential theft | All | User susceptibility | MFA, security awareness training |
| T-003 | Unauthorized access | A-001, A-005 | Overprivileged accounts | RBAC, quarterly access review |
| T-004 | Data exfiltration by insider | A-001, A-003 | Insufficient monitoring | DLP, audit logging |
| T-005 | Cloud misconfiguration | A-001, A-002 | Lack of posture management | AWS Config, cloud posture check |
| T-006 | Third-party / supply chain | All | Vendor access | Vendor risk assessments, MFA |
| T-007 | DDoS attack | A-002 | Limited capacity | CDN, AWS Shield |
| | | | | |

---

## 5. Risk Register

| Risk ID | Threat | Asset | Likelihood (1–5) | Impact (1–5) | Score | Level | Treatment | Owner | Due Date | Status |
|---------|--------|-------|-----------------|-------------|-------|-------|-----------|-------|----------|--------|
| R-001 | Ransomware | A-001, A-002 | 3 | 5 | 15 | High | Mitigate: immutable backups, network segmentation | [Name] | [Date] | In Progress |
| R-002 | Credential theft via phishing | All | 4 | 4 | 16 | High | Mitigate: enforce MFA, phishing simulation | [Name] | [Date] | Open |
| R-003 | Unauthorized access — insider | A-001 | 2 | 5 | 10 | High | Mitigate: least privilege review, UBA | [Name] | [Date] | Open |
| R-004 | Cloud misconfiguration | A-001 | 3 | 4 | 12 | High | Mitigate: IaC, cloud posture checks | [Name] | [Date] | In Progress |
| R-005 | Supply chain compromise | All | 2 | 4 | 8 | Medium | Mitigate: vendor assessments, SBOMs | [Name] | [Date] | Open |
| R-006 | DDoS | A-002 | 3 | 3 | 9 | Medium | Transfer: CDN + DDoS mitigation service | [Name] | [Date] | Completed |
| R-007 | Physical access — server room | A-001 | 1 | 4 | 4 | Low | Accept: colocation facility physical controls documented | [Name] | — | Accepted |
| | | | | | | | | | | |

---

## 6. Risk Treatment Plan

For each risk rated Medium or above:

### R-001 — Ransomware

**Current state:** Backups exist but are not immutable; no network segmentation between workloads.

**Treatment actions:**
- [ ] Enable S3 Object Lock / Azure Immutable Blob Storage for all backups
- [ ] Implement network segmentation between application and database tiers
- [ ] Test backup restoration monthly
- [ ] Deploy endpoint detection and response (EDR) on all servers

**Residual risk after treatment:** Likelihood 2 × Impact 5 = 10 (High → Medium after controls)

---

### R-002 — Credential Theft via Phishing

**Treatment actions:**
- [ ] Enforce MFA for all users with access to production systems
- [ ] Run quarterly phishing simulation (KnowBe4, Proofpoint, or equivalent)
- [ ] Implement DMARC, DKIM, SPF on all email-sending domains
- [ ] Deploy email security gateway

**Residual risk after treatment:** Likelihood 2 × Impact 4 = 8 (Medium)

---

## 7. Risk Acceptance Register

Risks that management has formally accepted rather than treated:

| Risk ID | Risk Description | Score | Reason for Acceptance | Accepted by | Date |
|---------|-----------------|-------|----------------------|-------------|------|
| R-007 | Physical server room access | 4 (Low) | Hosted in SOC 2 Type II certified colocation facility | [Name, Title] | [Date] |
| | | | | | |

---

## 8. Review and Approval

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Risk Owner | | | |
| CISO / Security Manager | | | |
| Management Representative | | | |

**Next scheduled review:** [DATE]

---

## Automate your ISO 27001 program

Filling this in by hand is the slow part. CATAAM pre-builds the full 93-control Annex A library, harvests evidence continuously from AWS, GitHub, and Jira, and generates your Statement of Applicability automatically.

- 👉 **[ISO 27001 compliance automation](https://cataam.com/compliance/iso27001/)** — automate the whole ISMS
- 📋 **[ISO 27001 certification checklist](https://cataam.com/blog/iso-27001-certification-checklist/)** — the 12 steps to certified
- 💸 **[How much does ISO 27001 cost?](https://cataam.com/blog/iso-27001-cost/)** — full 2026 cost breakdown

---

*Template maintained by the [Cataam](https://cataam.com) team. MIT License — copy and modify freely.*
