# Contributing to Cataam Security Toolkit

Thank you for contributing. This repository is the open-source initiative of the [Cataam](https://cataam.com) team, and every contribution makes it more valuable for the security community.

---

## What to Contribute

- **New tools** — security scripts that map findings to compliance frameworks
- **New CVE detection scripts** — especially within 48 hours of a major disclosure
- **Knowledge base improvements** — corrections, additions, better examples
- **Template updates** — as frameworks publish new versions (ISO 27001, PCI DSS, etc.)
- **Bug fixes** — broken scripts, outdated tool versions, incorrect control mappings

---

## Guidelines for New Tools

1. **Map to a framework** — every tool should map findings to at least one: CIS Benchmarks, ISO 27001, SOC 2, HIPAA, or PCI DSS.
2. **Include `--output` for JSON** — where possible, output structured findings so they can be imported into GRC tools.
3. **Minimal dependencies** — prefer stdlib over third-party where practical.
4. **Document usage** — add a section to the relevant folder's `README.md` with usage examples.
5. **No hardcoded credentials** — use environment variables or CLI flags.

---

## Branch Naming

Use the appropriate prefix so PRs are easy to triage at a glance:

| Prefix | Use for | Example |
|--------|---------|---------|
| `feat/` | New tools, new CVE scripts, new templates | `feat/gcp-posture-check` |
| `fix/` | Bug fixes, broken scripts, incorrect control mappings | `fix/ssl-audit-cipher-list` |
| `cve/` | CVE lab additions | `cve/CVE-2024-12345` |
| `docs/` | README, wiki, glossary, knowledge base only | `docs/iso27001-annex-a-update` |

Keep branch names lowercase and hyphen-separated. Branches that don't follow this convention will be asked to rename before review.

---

## Submitting a PR

1. Fork the repository
2. Create a branch using the convention above: `git checkout -b feat/my-tool`
3. Make your changes
4. Test your tool or template
5. Open a pull request — the PR template will prompt you for the required details

---

## CVE Lab Contributions

When submitting a new CVE detection script:
1. Create a folder: `cve-lab/CVE-YYYY-NNNNN/`
2. Include:
   - `README.md` with CVE details, CVSS score, compliance impact, and mitigation
   - Detection script (shell or Python)
3. Keep detection scripts defensive — they should read and report, not modify systems

---

*Questions? Open an issue on GitHub.*
