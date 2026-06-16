#!/usr/bin/env python3
"""Regenerate the 'CVEs Covered' index table in cve-lab/README.md from the CVE folders.

Each `cve-lab/CVE-YYYY-NNNNN/` directory is one entry; this reads its README.md for the
product/name (H1) and CVSS (severity table) and rebuilds the index table in place. Run by
`.github/workflows/cve-index.yml` on every push to main, and safe to run locally:

    python3 tools/gen_cve_index.py
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CVE_LAB = ROOT / "cve-lab"
README = CVE_LAB / "README.md"


def _meta(d: pathlib.Path) -> tuple[str, str, str]:
    cve = d.name
    name, cvss = cve, "—"
    rm = d / "README.md"
    if rm.exists():
        txt = rm.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"^#\s*" + re.escape(cve) + r"\s*[—-]+\s*(.+)$", txt, re.M)
        if m:
            name = m.group(1).strip()
        else:
            h = re.search(r"^#\s+(.+)$", txt, re.M)
            if h:
                name = h.group(1).strip()
        # Scan each CVSS line for a score and/or severity word independently, so table cells
        # like "| CVSS | 6.5 (MEDIUM) |" and prose like "CVSS 10.0 CRITICAL" both parse, and a
        # score-less "see advisory (HIGH)" still surfaces the severity.
        for line in txt.splitlines():
            if not re.search(r"CVSS", line, re.I):
                continue
            num = re.search(r"(\d{1,2}\.\d)", line)
            sev = re.search(r"(CRITICAL|HIGH|MEDIUM|LOW)", line, re.I)
            if num:
                cvss = num.group(1) + (f" {sev.group(1).upper()}" if sev else "")
                break
            if sev and cvss == "—":
                cvss = sev.group(1).upper()
    return cve, name, cvss


def _key(name: str) -> tuple[int, int]:
    m = re.match(r"CVE-(\d+)-(\d+)", name)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def main() -> int:
    dirs = sorted((d for d in CVE_LAB.iterdir() if d.is_dir() and d.name.startswith("CVE-")),
                  key=lambda d: _key(d.name), reverse=True)
    rows = ["| CVE | Product | CVSS | Folder |", "|-----|---------|------|--------|"]
    for d in dirs:
        cve, name, cvss = _meta(d)
        rows.append(f"| {cve} | {name} | {cvss} | [`{cve}/`](./{cve}/) |")
    table = "\n".join(rows)

    txt = README.read_text(encoding="utf-8")
    pat = re.compile(r"(## CVEs Covered\s*\n\s*\n).*?(\n\s*---\s*\n)", re.S)
    if not pat.search(txt):
        print("ERROR: '## CVEs Covered' section / trailing '---' not found", file=sys.stderr)
        return 1
    new = pat.sub(lambda m: m.group(1) + table + m.group(2), txt)
    if new != txt:
        README.write_text(new, encoding="utf-8")
        print(f"index updated: {len(dirs)} CVE(s)")
    else:
        print(f"index already current: {len(dirs)} CVE(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
