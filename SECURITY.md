# Security Policy

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)

## Supported Versions

We apply security fixes to the latest version of each tool in this repository. Older pinned versions are not backported.

| Component | Supported |
|-----------|-----------|
| `tools/` scripts (latest) | ✅ |
| `cve-lab/` detection scripts (latest) | ✅ |
| Pinned/forked versions | ❌ |

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via one of:

- **GitHub private disclosure** — use the "Report a vulnerability" button on the [Security tab](../../security/advisories/new) of this repository.
- **Email** — send details to [security@cataam.com](mailto:security@cataam.com). Encrypt with our PGP key if the details are sensitive (key available on request).

### What to include

- A clear description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- The affected file(s) and version/commit
- Any suggested remediation, if you have one

### What to expect

| Timeline | Action |
|----------|--------|
| Within 48 hours | Acknowledgement of your report |
| Within 7 days | Initial assessment and severity rating |
| Within 30 days | Patch or mitigation for confirmed vulnerabilities |
| Post-fix | Public disclosure coordinated with the reporter |

We follow [responsible disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html). Reporters who follow this policy will be credited in the advisory unless they prefer to remain anonymous.

---

## Scope

This repository contains **security tooling and reference content**. In-scope reports include:

- Vulnerabilities in the scripts themselves (e.g. command injection, unsafe temp file handling, credential leakage)
- False-negative detections that could lead users to believe a system is secure when it is not
- Supply-chain issues in any declared dependencies

Out of scope:

- Theoretical risks without a realistic attack path
- Issues in third-party tools that our scripts invoke (report those upstream)
- Social engineering

---

## Security Considerations When Using These Tools

- **`env-hardener.sh --fix`** modifies system configuration. Run `--dry-run` first and review all findings before applying changes.
- **`cloud-posture-check.py`** requires AWS credentials. Use a dedicated read-only IAM role; never pass credentials via CLI arguments in shared environments.
- **`cve-lab/` detection scripts** are read-only by design. They should never be run with write access to production systems.
- All scripts output findings to local files by default. Treat output files as potentially sensitive — they describe your attack surface.

---

*Questions about this policy? Open a non-security issue or email [security@cataam.com](mailto:security@cataam.com).*
