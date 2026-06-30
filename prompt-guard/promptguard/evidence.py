"""Audit-evidence emitter.

Every redaction becomes a structured, Cataam-importable event that maps the prevented leak
to the compliance controls it provides evidence for (ISO 42001, NIST AI RMF, EU AI Act, ...).
This is what makes Prompt Guard *governance*, not just a redactor: a real, queryable record that
"data egress to AI was controlled" — the artifact auditors and the EU AI Act (Art. 12) ask for.
Crucially, events contain only NON-sensitive previews, never the raw secret.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .detectors import Finding, max_severity

CATAAM_IMPORT_VERSION = "1.0"
TOOL = "cataam-prompt-guard"
TOOL_VERSION = "0.1.0"

_CONTROLS = json.loads(Path(__file__).with_name("controls.json").read_text())


def _controls_for(categories) -> dict:
    out = {}
    for cat in categories:
        for fw, ctrls in _CONTROLS["by_category"].get(cat, {}).items():
            out.setdefault(fw, [])
            for c in ctrls:
                if c not in out[fw]:
                    out[fw].append(c)
    return out


def build_event(findings: List[Finding], *, destination: str = "unknown",
                action: str = "redact", actor: str = None, surface: str = "cli") -> dict:
    """Build one Cataam-importable egress-control event from a scan's findings."""
    cats = sorted({f.category for f in findings})
    sev = max_severity(findings)
    # A stable, privacy-preserving id for the prompt (hash of content, not the content).
    return {
        "cataam_import_version": CATAAM_IMPORT_VERSION,
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "event_type": "ai_egress_control",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor or os.environ.get("USER") or "unknown",
        "surface": surface,                 # browser | desktop | ide | cli | proxy
        "destination": destination,         # e.g. chat.openai.com, claude.ai
        "action": action,                   # redact | block | allow | coach
        "max_severity": sev,
        "categories": cats,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "controls": _controls_for(cats),    # <-- the moat: mapped, auditor-ready
        "frameworks": _CONTROLS["frameworks"],
    }


def write_event(event: dict, path: str) -> None:
    """Append the event as one JSON line (JSONL) — easy to stream into a SIEM/GRC."""
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")
