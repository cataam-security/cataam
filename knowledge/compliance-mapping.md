# Multi-Framework Compliance Mapping

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

Cross-reference between the five most common compliance frameworks in enterprise security programs. Use this to avoid duplicate work when pursuing multiple certifications simultaneously.

---

## The Big Five

| Framework | Governing Body | Primary Audience | Audit Type |
|-----------|---------------|------------------|-----------|
| CIS Benchmarks | Center for Internet Security | Technical / DevOps | Self-assessment |
| ISO 27001:2022 | ISO / IEC | All industries | Third-party certification |
| SOC 2 Type II | AICPA | SaaS / Service companies | Third-party attestation |
| HIPAA Security Rule | HHS (US) | Healthcare / Business Associates | Self-assessment + OCR audit |
| PCI DSS 4.0 | PCI SSC | Cardholder data handlers | QSA audit or SAQ |

---

## Control Mapping: Access Control

| Requirement | CIS | ISO 27001 | SOC 2 | HIPAA | PCI DSS 4.0 |
|-------------|-----|-----------|-------|-------|-------------|
| MFA for privileged accounts | CIS 4.1 | A.8.2 | CC6.1 | § 164.312(d) | Req 8.4.2 |
| Unique user IDs | CIS 4.2 | A.5.16 | CC6.1 | § 164.312(a)(2)(i) | Req 8.2.1 |
| Least privilege | CIS 4.3 | A.8.2 | CC6.3 | § 164.312(a)(1) | Req 7.2 |
| Access reviews (quarterly) | — | A.5.18 | CC6.2 | § 164.308(a)(3) | Req 7.2.3 |
| Session timeout | CIS 5.1.9 | A.8.3 | CC6.1 | § 164.312(a)(2)(iii) | Req 8.6.3 |
| Password complexity | CIS 4.1 | A.5.17 | CC6.1 | § 164.308(a)(5) | Req 8.3.6 |

---

## Control Mapping: Vulnerability Management

| Requirement | CIS | ISO 27001 | SOC 2 | HIPAA | PCI DSS 4.0 |
|-------------|-----|-----------|-------|-------|-------------|
| Asset inventory | CIS 1.1 | A.8.1 | CC6.1 | § 164.310(d) | Req 12.5.1 |
| Vulnerability scanning | CIS 7.1 | A.8.8 | CC7.1 | § 164.308(a)(8) | Req 11.3 |
| Patch management policy | CIS 7.3 | A.8.8 | CC7.1 | § 164.308(a)(8) | Req 6.3.3 |
| Critical patches < 30 days | CIS 7.3 | A.8.8 | CC7.1 | — | Req 6.3.3 |
| Penetration testing | CIS 18 | A.8.8 | CC4.2 | — | Req 11.4 |

---

## Control Mapping: Logging and Monitoring

| Requirement | CIS | ISO 27001 | SOC 2 | HIPAA | PCI DSS 4.0 |
|-------------|-----|-----------|-------|-------|-------------|
| Audit logging enabled | CIS 8.1 | A.8.15 | CC7.2 | § 164.312(b) | Req 10.2 |
| Log retention ≥ 1 year | CIS 8.3 | A.8.15 | CC7.2 | § 164.312(b) | Req 10.7 |
| Centralized log management | CIS 8.9 | A.8.15 | CC7.2 | § 164.312(b) | Req 10.5.1 |
| Alerting on critical events | CIS 8.11 | A.8.16 | CC7.3 | § 164.308(a)(1) | Req 10.6 |
| Clock synchronization (NTP) | CIS 8.4 | A.8.17 | CC7.2 | — | Req 10.6.3 |

---

## Control Mapping: Encryption

| Requirement | CIS | ISO 27001 | SOC 2 | HIPAA | PCI DSS 4.0 |
|-------------|-----|-----------|-------|-------|-------------|
| Encryption in transit (TLS 1.2+) | CIS 3.10 | A.8.24 | CC6.7 | § 164.312(e)(1) | Req 4.2.1 |
| No deprecated protocols (TLS 1.0/1.1) | CIS 3.10 | A.8.24 | CC6.7 | § 164.312(e)(2)(ii) | Req 4.2.1 |
| Encryption at rest | CIS 3.11 | A.8.24 | CC6.7 | § 164.312(a)(2)(iv) | Req 3.5.1 |
| Key management documented | — | A.8.24 | CC6.7 | § 164.312(a)(2)(iv) | Req 3.7 |

---

## Control Mapping: Incident Response

| Requirement | CIS | ISO 27001 | SOC 2 | HIPAA | PCI DSS 4.0 |
|-------------|-----|-----------|-------|-------|-------------|
| Incident response plan | CIS 17.1 | A.5.24 | CC7.3 | § 164.308(a)(6) | Req 12.10.1 |
| IR plan tested annually | CIS 17.5 | A.5.26 | CC7.5 | § 164.308(a)(6) | Req 12.10.2 |
| Breach notification procedure | — | A.5.25 | CC7.3 | § 164.408 | Req 12.10.4 |
| Forensic evidence preservation | CIS 17.7 | A.5.28 | CC7.4 | § 164.308(a)(6) | Req 12.10.5 |
| Lessons learned process | — | A.5.27 | CC7.5 | — | Req 12.10.6 |

---

## How to Use This Mapping

**Starting ISO 27001 and you already have SOC 2?**
You have significant coverage. ISO 27001 adds a formal risk management methodology and ISMS documentation requirements that SOC 2 doesn't prescribe. Focus your gap work on the risk register, Statement of Applicability, and internal audit function.

**Starting PCI DSS and you want to add SOC 2?**
PCI DSS 4.0 Req 10 (logging), Req 7 (access control), and Req 11 (vulnerability testing) map well to SOC 2 CC7 and CC6. Your PCI evidence will partially satisfy SOC 2 testing requirements — coordinate with your auditor.

**Starting with nothing and HIPAA is required?**
HIPAA is prescriptive about *what* but not *how*. Using the CIS Benchmarks as your technical baseline satisfies most of the Security Rule's technical safeguard requirements (§ 164.312), and gives you documented evidence of implementation.

---

*Maintained by the [Cataam](https://cataam.com) team. For GRC automation and continuous compliance monitoring, visit [cataam.com](https://cataam.com).*
