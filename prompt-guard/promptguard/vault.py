"""Reversible tokenization vault.

Redaction replaces each sensitive span with a stable placeholder (e.g. «PG:AWS_ACCESS_KEY_ID:1»)
and remembers the mapping locally so the model's *response* can be re-hydrated — the user still
gets a useful answer, but the secret never leaves the machine. The vault is in-memory by default;
nothing is persisted unless you explicitly snapshot it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict

_PLACEHOLDER_RE = re.compile(r"«PG:([A-Z0-9_]+):(\d+)»")


@dataclass
class Vault:
    """Bidirectional map between placeholders and original sensitive values (session-scoped)."""
    _to_original: Dict[str, str] = field(default_factory=dict)   # placeholder -> original
    _to_placeholder: Dict[str, str] = field(default_factory=dict)  # original -> placeholder
    _counters: Dict[str, int] = field(default_factory=dict)

    def placeholder_for(self, rule_id: str, original: str) -> str:
        """Stable placeholder per distinct value, so the same secret maps consistently."""
        if original in self._to_placeholder:
            return self._to_placeholder[original]
        token = rule_id.upper().replace("-", "_")
        self._counters[token] = self._counters.get(token, 0) + 1
        ph = f"«PG:{token}:{self._counters[token]}»"
        self._to_original[ph] = original
        self._to_placeholder[original] = ph
        return ph

    def restore(self, text: str) -> str:
        """Re-insert original values into a model response (or any text)."""
        def repl(m):
            return self._to_original.get(m.group(0), m.group(0))
        return _PLACEHOLDER_RE.sub(repl, text)

    def is_empty(self) -> bool:
        return not self._to_original
