"""Claude Code `UserPromptSubmit` hook — the interactive-terminal guard.

A shell wrapper can only guard one-shot/piped calls. Inside the interactive Claude Code TUI,
the supported interception point is a UserPromptSubmit hook. That hook cannot rewrite the prompt
(Claude Code has no prompt-replacement field), so Prompt Guard runs **fail-closed**: if a prompt
contains a secret/PII, it BLOCKS submission (exit 2) — the sensitive text never reaches the model —
and records an audit-evidence event (action=block). Clean prompts pass straight through (exit 0).

Wire it up:  promptguard install-hook        (merges into ~/.claude/settings.json)
Manually:    "hooks": {"UserPromptSubmit": [{"type":"command","command":"promptguard hook"}]}
"""
import json
import os
import sys

from .engine import Engine
from .evidence import build_event, write_event

PG_HOME = os.path.expanduser(os.environ.get("PROMPTGUARD_HOME", "~/.promptguard"))


def run_hook() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}
    prompt = payload.get("user_input") or payload.get("prompt") or ""
    if not prompt:
        return 0   # nothing to inspect — allow

    res = Engine().inspect(prompt, surface="ide", destination="claude-code", action="block")
    if res.clean:
        return 0   # allow

    # record the prevented egress as evidence (previews only, never the raw secret)
    try:
        os.makedirs(PG_HOME, exist_ok=True)
        event = build_event(res.findings, destination="claude-code", action="block", surface="ide")
        write_event(event, os.path.join(PG_HOME, "evidence.jsonl"))
    except Exception:
        pass

    items = "; ".join(f"{f.label} ({f.redacted_preview()})" for f in res.findings)
    sys.stderr.write(
        "\n🛡  Prompt Guard blocked this prompt — it was NOT sent to the model.\n"
        f"   Detected {len(res.findings)} sensitive item(s): {items}\n"
        "   Remove or replace the secret/PII and resend. The blocked egress was logged\n"
        "   as ISO 42001 / EU AI Act Art.12 evidence in ~/.promptguard/evidence.jsonl.\n"
    )
    return 2   # block (Claude Code erases the prompt and shows stderr)


def install_hook() -> int:
    """Merge the UserPromptSubmit hook into ~/.claude/settings.json (idempotent)."""
    settings_path = os.path.expanduser("~/.claude/settings.json")
    os.makedirs(os.path.dirname(settings_path), exist_ok=True)
    data = {}
    if os.path.exists(settings_path):
        try:
            data = json.load(open(settings_path))
        except Exception:
            sys.stderr.write(f"could not parse {settings_path}; not modifying it.\n")
            return 1
    # Resolve an absolute command so it works even when Claude Code's hook shell doesn't have
    # the venv on PATH: prefer the `promptguard` console script, else this exact interpreter.
    import shutil
    exe = shutil.which("promptguard")
    command = f'"{exe}" hook' if exe else f'"{sys.executable}" -m promptguard.cli hook'

    hooks = data.setdefault("hooks", {})
    ups = hooks.setdefault("UserPromptSubmit", [])
    entry = {"type": "command", "command": command, "timeout": 15}
    if any(isinstance(h, dict) and "promptguard" in str(h.get("command", "")) for h in ups):
        sys.stderr.write("Prompt Guard hook already installed in ~/.claude/settings.json\n")
        return 0
    ups.append(entry)
    json.dump(data, open(settings_path, "w"), indent=2)
    sys.stderr.write(
        "✓ Installed Prompt Guard UserPromptSubmit hook -> ~/.claude/settings.json\n"
        "  Interactive Claude Code prompts containing secrets/PII will now be blocked.\n"
        "  Restart the `claude` session (or run /hooks) to load it.\n"
    )
    return 0
