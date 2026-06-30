"""Detection engine for Prompt Guard.

Loads detection rules from rules.json (regex / entropy / Luhn) and scans text for
secrets, PII and other sensitive tokens. Pure standard library — no third-party deps —
so it runs anywhere a laptop has Python 3.8+.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

_RULES_PATH = Path(__file__).with_name("rules.json")

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def max_severity(findings) -> str:
    if not findings:
        return "NONE"
    return max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity


@dataclass
class Finding:
    """One detected sensitive span."""
    rule_id: str
    label: str
    category: str          # secret | pii | code
    severity: str
    start: int
    end: int
    match: str
    detail: str = ""

    def redacted_preview(self) -> str:
        """A non-sensitive preview for logs/evidence — never the raw secret."""
        m = self.match
        if len(m) <= 8:
            return m[0] + "***"
        return f"{m[:3]}…{m[-2:]} ({len(m)} chars)"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "label": self.label,
            "category": self.category,
            "severity": self.severity,
            "start": self.start,
            "end": self.end,
            "preview": self.redacted_preview(),
            "detail": self.detail,
        }


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    checksum, parity = 0, len(d) % 2
    for i, n in enumerate(d):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")


class Detector:
    """Compiled rule set. Construct once, reuse across scans."""

    def __init__(self, rules: Optional[List[dict]] = None):
        if rules is None:
            data = json.loads(_RULES_PATH.read_text())
            rules = data["rules"]
        self.regex_rules = []
        self.entropy_rules = []
        for r in rules:
            if r.get("entropy"):
                self.entropy_rules.append(r)
            elif r.get("pattern"):
                self.regex_rules.append((r, re.compile(r["pattern"])))

    def scan(self, text: str) -> List[Finding]:
        findings: List[Finding] = []
        spans: List[tuple] = []  # (start, end) already-claimed, to dedupe overlaps

        def claim(s, e):
            for (cs, ce) in spans:
                if s < ce and e > cs:
                    return False
            spans.append((s, e))
            return True

        for rule, rx in self.regex_rules:
            for m in rx.finditer(text):
                # if the rule has a capture group, the secret is the group; else the whole match
                grp = m.group(1) if rx.groups else m.group(0)
                gs = m.start(1) if rx.groups else m.start(0)
                ge = m.end(1) if rx.groups else m.end(0)
                if rule.get("luhn") and not _luhn_ok(grp):
                    continue
                if not claim(gs, ge):
                    continue
                findings.append(Finding(rule["id"], rule["label"], rule["category"],
                                        rule["severity"], gs, ge, grp))

        for rule in self.entropy_rules:
            cfg = rule["entropy"]
            for m in _ENTROPY_TOKEN_RE.finditer(text):
                tok = m.group(0)
                if len(tok) < cfg.get("min_len", 24):
                    continue
                if _shannon_entropy(tok) < cfg.get("threshold", 4.0):
                    continue
                if not claim(m.start(), m.end()):
                    continue
                findings.append(Finding(rule["id"], rule["label"], rule["category"],
                                        rule["severity"], m.start(), m.end(), tok,
                                        detail=f"entropy={_shannon_entropy(tok):.2f}"))

        findings.sort(key=lambda f: f.start)
        return findings

    @staticmethod
    def max_severity(findings: List[Finding]) -> str:
        return max_severity(findings)
