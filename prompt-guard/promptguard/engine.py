"""Prompt Guard engine — the local, on-device core that ties detection → reversible
redaction → audit evidence together. Everything here runs locally; no prompt text ever
leaves the machine for the scanning itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .detectors import Detector, Finding
from .evidence import build_event
from .vault import Vault


@dataclass
class GuardResult:
    original: str
    redacted: str
    findings: List[Finding]
    vault: Vault
    event: dict

    @property
    def clean(self) -> bool:
        return not self.findings


class Engine:
    def __init__(self, detector: Optional[Detector] = None):
        self.detector = detector or Detector()

    def inspect(self, text: str, *, destination: str = "unknown", surface: str = "cli",
                actor: str = None, action: str = "redact",
                vault: Optional[Vault] = None) -> GuardResult:
        """Scan text, produce a redacted copy with reversible placeholders, and an audit event."""
        findings = self.detector.scan(text)
        vault = vault or Vault()
        # rebuild the string with placeholders, walking spans right-to-left to keep offsets valid
        redacted = text
        for f in sorted(findings, key=lambda x: x.start, reverse=True):
            ph = vault.placeholder_for(f.rule_id, f.match)
            redacted = redacted[:f.start] + ph + redacted[f.end:]
        event = build_event(findings, destination=destination, action=action,
                            actor=actor, surface=surface)
        return GuardResult(text, redacted, findings, vault, event)

    @staticmethod
    def restore(text: str, vault: Vault) -> str:
        """Re-hydrate a model response so the user sees real values, not placeholders."""
        return vault.restore(text)
