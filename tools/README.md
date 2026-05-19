<p align="center">
  <a href="https://cataam.com">
    <img src="../assets/logo.svg" alt="Cataam" height="50" />
  </a>
</p>

# Tools

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](../LICENSE)

Practical security scripts that produce audit-ready evidence. Each tool maps its findings to one or more compliance frameworks and outputs structured JSON.

---

## Tools

| Script | Purpose | Frameworks |
|--------|---------|-----------|
| [`env-hardener.sh`](./env-hardener.sh) | Linux CIS Benchmark hardening | CIS L1/L2, ISO 27001 A.8 |
| [`cve-scanner.py`](./cve-scanner.py) | NVD CVE lookup + control mapping | ISO 27001 A.12, SOC 2 CC7 |
| [`cloud-posture-check.py`](./cloud-posture-check.py) | AWS CIS Foundations audit | CIS AWS v1.5, SOC 2 CC6 |
| [`ssl-tls-audit.py`](./ssl-tls-audit.py) | TLS/cipher suite audit | PCI DSS 4.0 Req 4.2, SOC 2 CC6 |

---

## Installation

```bash
pip install -r requirements.txt
```

All Python tools require Python 3.8+. The shell scripts require bash 4+ and standard Linux utilities (`awk`, `grep`, `ss`, `sysctl`).

---

## env-hardener.sh

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

Applies CIS Benchmark Level 1 and Level 2 hardening checks to a Linux host. Every check is annotated with its CIS control ID so findings map directly to audit evidence.

```bash
sudo ./env-hardener.sh [OPTIONS]

Options:
  --level 1|2        CIS Benchmark level (default: 1)
  --report FILE      Write findings to FILE (default: stdout)
  --json FILE        Write Cataam-importable JSON to FILE
  --fix              Apply remediations automatically (use with caution)
  --dry-run          Report findings without making changes
```

**Example — audit only, export for Cataam:**
```bash
sudo ./env-hardener.sh --dry-run --json cataam-hardening.json
```

**CIS Controls covered:** 1.1–1.8 (filesystem), 3.1–3.6 (network), 4.1–4.4 (access control), 5.1–5.4 (SSH), 6.1–6.3 (logging).

---

## cve-scanner.py

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

Queries the NVD API for CVEs affecting a product/version, scores them with CVSS v3, and maps each finding to ISO 27001 Annex A controls and SOC 2 criteria.

```bash
python cve-scanner.py [OPTIONS]

Options:
  --product TEXT     Product name to scan (required)
  --version TEXT     Specific version to check
  --severity TEXT    Minimum severity: LOW|MEDIUM|HIGH|CRITICAL (default: MEDIUM)
  --output FILE      Write Cataam-importable JSON to FILE
  --days INT         Look back N days for new CVEs (default: 90)
```

**Example:**
```bash
python cve-scanner.py --product "apache httpd" --version 2.4.51 --severity HIGH --output findings.json
```

---

## cloud-posture-check.py

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

Audits an AWS account against the CIS AWS Foundations Benchmark v1.5. Requires `boto3` and appropriate read-only IAM permissions (see `iam-policy.json`).

```bash
python cloud-posture-check.py [OPTIONS]

Options:
  --profile TEXT     AWS CLI profile to use
  --region TEXT      AWS region (default: us-east-1)
  --output FILE      Write Cataam-importable JSON to FILE
  --section TEXT     Run only a specific CIS section (iam|storage|logging|monitoring|networking)
```

**Example:**
```bash
python cloud-posture-check.py --profile prod-readonly --output aws-posture.json
```

---

## ssl-tls-audit.py

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

Checks a host's TLS configuration for PCI DSS 4.0 requirement 4.2 compliance. Detects deprecated protocols, weak cipher suites, and certificate issues.

```bash
python ssl-tls-audit.py [OPTIONS]

Options:
  --host TEXT        Hostname or IP to audit (required)
  --port INT         Port to check (default: 443)
  --pci              Apply strict PCI DSS 4.0 pass/fail thresholds
  --output FILE      Write Cataam-importable JSON to FILE
  --timeout INT      Connection timeout in seconds (default: 10)
```

**Example:**
```bash
python ssl-tls-audit.py --host api.example.com --pci --output tls-findings.json
```
