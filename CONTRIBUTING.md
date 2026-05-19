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

## Submitting a PR

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-tool`
3. Make your changes
4. Test your tool or template
5. Open a pull request with a clear description of what it does and which framework it covers

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
