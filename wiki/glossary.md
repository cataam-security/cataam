# Security & GRC Glossary

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

Plain-English definitions for GRC, compliance, and security operations terms. No jargon without explanation.

---

## A

**Access Control List (ACL)**  
A set of rules that defines which users or systems can access a resource and what actions they can perform. AWS security groups are a type of ACL.

**Attack Surface**  
The sum of all points where an attacker could attempt to enter or extract data from a system. Reducing the attack surface is a core principle of defense-in-depth.

**Attack Surface Management (ASM)**  
The continuous process of discovering, inventorying, and monitoring an organization's external-facing assets to identify and reduce exposure.

**Audit Trail**  
A chronological record of system activities that enables reconstruction of events. Required by ISO 27001 A.8.15, SOC 2 CC7.2, HIPAA § 164.312(b), and PCI DSS Req 10.

---

## B

**Business Associate Agreement (BAA)**  
Under HIPAA, a contract between a covered entity and a business associate that establishes each party's responsibilities for protecting ePHI. Required before sharing ePHI with any third party.

**Business Continuity Plan (BCP)**  
Documentation of how an organization will continue operating during and after a significant disruption. Distinct from Disaster Recovery (DR), which focuses on IT systems.

---

## C

**CIS Benchmark**  
Security configuration standards published by the Center for Internet Security. CIS Benchmarks provide specific, prescriptive hardening guidance for operating systems, cloud platforms, and applications. Level 1 = basic hygiene; Level 2 = more restrictive, may impact usability.

**CMVP (Cryptographic Module Validation Program)**  
NIST program that validates cryptographic modules against FIPS 140-2/140-3. Required for some federal and regulated industry use cases.

**Compliance**  
Adherence to laws, regulations, and standards. Compliance does not equal security — it's a minimum bar, not a ceiling.

**Control**  
A measure that modifies risk. Controls can be preventive (prevent the risk), detective (identify when a risk materializes), or corrective (respond to a risk that has materialized).

**CVSS (Common Vulnerability Scoring System)**  
A standardized numerical score (0–10) representing the severity of a security vulnerability. CVSS v3.1 considers: Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality/Integrity/Availability impact.

**CVE (Common Vulnerabilities and Exposures)**  
A standardized identifier for publicly disclosed security vulnerabilities, maintained by MITRE. Format: CVE-YYYY-NNNNN. The NVD publishes CVSS scores for CVEs.

---

## D

**Defense in Depth**  
A security strategy that layers multiple controls so that if one fails, others remain in place. Example: MFA + network segmentation + endpoint protection + encryption at rest.

**DLP (Data Loss Prevention)**  
Technology or processes that detect and prevent unauthorized transmission of sensitive data outside an organization.

---

## E

**ePHI (Electronic Protected Health Information)**  
Under HIPAA, individually identifiable health information that is created, received, maintained, or transmitted electronically. Protected by the HIPAA Security Rule.

**Evidence (audit context)**  
Documentation that demonstrates a control is operating effectively. Types: screenshots, logs, policy documents, configuration exports, signed forms, tickets. Auditors sample evidence to conclude whether controls are working.

---

## F

**FIPS 140-2 / 140-3**  
US federal standard for cryptographic module security requirements. Required for systems used in US government contexts. FIPS 140-3 is the current version (2024+).

---

## G

**Gap Assessment**  
An analysis that compares an organization's current security or compliance posture against a target framework, identifying what's missing or needs improvement.

**GRC (Governance, Risk, and Compliance)**  
The integrated framework for how an organization governs itself, manages risk, and ensures compliance. GRC programs align business objectives with risk tolerance and regulatory obligations.

---

## I

**iASM (Integrated Attack Surface Management)**  
An evolution of ASM that correlates external exposure data with internal vulnerability data and threat intelligence to prioritize remediation.

**Incident Response Plan (IRP)**  
Documented procedures for detecting, containing, eradicating, and recovering from security incidents. Required by ISO 27001 A.5.24, SOC 2 CC7.3, HIPAA § 164.308(a)(6), PCI DSS Req 12.10.

**ISO 27001**  
International standard for Information Security Management Systems (ISMS). Organizations can be certified against it by accredited third-party auditors. The 2022 version has 93 Annex A controls.

---

## L

**Least Privilege**  
A security principle stating that users, processes, and systems should have only the minimum permissions needed to perform their function. Fundamental to access control in every major framework.

**Log Retention**  
The period for which security and audit logs must be kept. Minimums: SOC 2 — as required by testing period; HIPAA — 6 years; PCI DSS — 12 months (3 months immediately available).

---

## M

**MFA (Multi-Factor Authentication)**  
Authentication requiring two or more factors: something you know (password), something you have (token, phone), something you are (biometric). Required by PCI DSS 4.0 Req 8.4.2, SOC 2 CC6.1, CIS Control 6.

**MITRE ATT&CK**  
A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. Used for threat modeling, detection engineering, and red team planning.

---

## N

**NVD (National Vulnerability Database)**  
NIST-maintained repository of CVE data enriched with CVSS scores, CWE classifications, and CPE product identifiers. The authoritative public source for vulnerability information.

---

## P

**PCI DSS (Payment Card Industry Data Security Standard)**  
Security standard for organizations that handle cardholder data. Maintained by the PCI Security Standards Council. Current version: 4.0. Enforced through contracts with card brands; non-compliance can result in fines and loss of payment processing ability.

**Penetration Testing**  
Authorized simulated attack on a system to evaluate security posture. Distinct from vulnerability scanning (automated) — pentesting involves manual exploitation and reasoning. Required annually by PCI DSS Req 11.4.

**POA&M (Plan of Action and Milestones)**  
A document tracking identified security deficiencies, planned remediation actions, resources, and target completion dates. Common in US federal/FedRAMP contexts; analogous to a risk treatment plan.

---

## R

**RBAC (Role-Based Access Control)**  
Access control model where permissions are assigned to roles, and users are assigned to roles. Simplifies access management and supports least privilege. Required by SOC 2 CC6.3, ISO 27001 A.8.2.

**Risk**  
The potential for loss or harm related to technical or physical infrastructure. Expressed as: Risk = Likelihood × Impact.

**Risk Acceptance**  
A formal decision by management to accept a risk rather than treating it. Must be documented, have a named owner, and be reviewed periodically.

**Risk Register**  
A document listing identified risks, their scores, treatment decisions, owners, and status. Central artifact of both ISO 27001 and SOC 2 audit programs.

---

## S

**SAST (Static Application Security Testing)**  
Analysis of source code for security vulnerabilities without executing the program. Examples: Semgrep, SonarQube, Checkmarx.

**SBOM (Software Bill of Materials)**  
A formal record of all components in a software product, including libraries and dependencies with their versions. Critical for supply chain security and vulnerability management.

**SOC 2 (Service Organization Control 2)**  
An attestation standard by the AICPA for service organizations. Based on Trust Service Criteria (TSC): Security, Availability, Confidentiality, Processing Integrity, Privacy. Type I = point-in-time; Type II = over a period (typically 12 months).

**SOC 2 Type II**  
The more rigorous and commonly required form of SOC 2 attestation, covering a defined period (typically 6–12 months). Demonstrates controls were operating effectively continuously, not just at a single point in time.

---

## T

**TLS (Transport Layer Security)**  
Cryptographic protocol for securing data in transit. TLS 1.2 and 1.3 are current. TLS 1.0 and 1.1 are deprecated and prohibited by PCI DSS 4.0, ISO 27001, and most enterprise security policies.

**Threat Intelligence**  
Evidence-based knowledge about existing or emerging threats. Sources: CISA alerts, NVD, ISAC feeds, dark web monitoring. Required by ISO 27001:2022 A.5.7 (new in 2022).

**Trust Service Criteria (TSC)**  
The criteria used by SOC 2 auditors, defined by the AICPA. The Common Criteria (CC) cover security controls applicable to all SOC 2 reports; additional criteria (A, C, PI, P) are added for availability, confidentiality, processing integrity, and privacy.

---

## V

**Vulnerability**  
A weakness in a system that can be exploited to compromise confidentiality, integrity, or availability. Distinct from a threat (the actor or event that exploits it) and a risk (the potential impact).

**Vulnerability Management**  
The ongoing process of identifying, evaluating, prioritizing, remediating, and reporting on vulnerabilities. Defined SLAs: Critical < 24h, High < 7 days, Medium < 30 days is a common standard.

---

*Maintained by the [Cataam](https://cataam.com) team. Contributions welcome — open a PR if a term is missing or out of date.*
