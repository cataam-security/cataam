#!/usr/bin/env python3
"""Prompt Guard CLI.

    promptguard wrap -- claude -p "why does AKIA... 403?"   # ★ transparent: guard ANY LLM CLI in place
    promptguard install                              # print shell snippet so `claude`/`ask` are auto-guarded
    promptguard scan    < prompt.txt                 # detect only (exit 1 if sensitive found)
    promptguard redact  < prompt.txt --output ev.json  # redacted prompt to stdout, evidence to JSON
    echo "$RESPONSE" | promptguard restore --vault v.json   # re-hydrate a model response
    promptguard serve   --port 8765                  # local API for the browser extension

Pure stdlib. `pip install rich` for colour (optional).
"""
import argparse
import json
import os
import sys

from . import __version__
from .engine import Engine
from .evidence import build_event, write_event

PG_HOME = os.path.expanduser(os.environ.get("PROMPTGUARD_HOME", "~/.promptguard"))

try:
    from rich.console import Console
    _c = Console(stderr=True)
    def err(msg): _c.print(msg)
except Exception:
    def err(msg): print(msg, file=sys.stderr)


def _read_stdin() -> str:
    return sys.stdin.read()


def cmd_scan(args):
    eng = Engine()
    res = eng.inspect(_read_stdin(), surface=args.surface, destination=args.destination)
    if res.clean:
        err("[green]✓ clean — no sensitive data detected[/green]" if 'rich' in sys.modules else "clean")
        return 0
    err(f"⚠ {len(res.findings)} finding(s) [{res.event['max_severity']}]:")
    for f in res.findings:
        err(f"  [{f.severity}] {f.label}: {f.redacted_preview()}")
    if args.output:
        write_event(res.event, args.output)
        err(f"evidence -> {args.output}")
    return 1


def cmd_redact(args):
    eng = Engine()
    res = eng.inspect(_read_stdin(), surface=args.surface, destination=args.destination)
    sys.stdout.write(res.redacted)            # safe-to-send prompt on stdout
    if args.output:
        write_event(res.event, args.output)
    if args.vault and not res.vault.is_empty():
        json.dump(res.vault._to_original, open(args.vault, "w"))   # for later restore
    err(f"redacted {len(res.findings)} span(s); "
        + (f"vault -> {args.vault}" if args.vault else "vault not saved (use --vault)"))
    return 0


def cmd_restore(args):
    from .vault import Vault
    v = Vault()
    v._to_original = json.load(open(args.vault))
    sys.stdout.write(v.restore(_read_stdin()))
    return 0


def cmd_serve(args):
    from .server import serve
    serve(host=args.host, port=args.port, evidence_log=args.output)
    return 0


def cmd_push(args):
    """Push the evidence JSONL to a Cataam platform — it latches each event as audit evidence for
    the AI data-egress control (ISO 42001 / NIST AI RMF / EU AI Act Art.12)."""
    import os, urllib.request, urllib.error
    events = [json.loads(l) for l in open(args.input) if l.strip()]
    url = (args.url or os.environ.get("CATAAM_URL", "")).rstrip("/") + "/api/ai-gov/ccm/egress-evidence"
    headers = {"Content-Type": "application/json"}
    token = args.token or os.environ.get("CATAAM_TOKEN", "")
    key = args.api_key or os.environ.get("CATAAM_API_KEY", "")
    if token:                                   # a logged-in user's JWT (Authorization: Bearer)
        headers["Authorization"] = f"Bearer {token}"
    if key:                                     # or an org integration API key (X-API-Key)
        headers["X-API-Key"] = key
    req = urllib.request.Request(url, data=json.dumps({"events": events}).encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read().decode()
    except urllib.error.HTTPError as e:
        err(f"push failed [{e.code}] {url}: {e.read().decode()[:300]}")
        return 1
    err(f"pushed {len(events)} event(s) -> {url}: {body}")
    return 0


def _load_vault(path):
    from .vault import Vault
    v = Vault()
    if path and os.path.exists(path):
        v._to_original = json.load(open(path))
        v._to_placeholder = {orig: ph for ph, orig in v._to_original.items()}
    return v


def cmd_wrap(args):
    """Transparently guard a downstream LLM CLI. Redacts every secret/PII span found in the
    command's arguments *and* its piped stdin BEFORE the process is exec'd, then re-hydrates any
    «PG:…» placeholders in its streamed output so the answer is still useful. Drop-in prefix:

        promptguard wrap -- claude -p "my deploy 403s with AKIA…, why?"

    The user types their question once, normally; the secret never leaves the machine."""
    import subprocess
    cmd = list(args.cmd or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        err("usage: promptguard wrap [--destination NAME] -- <llm-command> [args...]")
        return 2

    os.makedirs(PG_HOME, exist_ok=True)
    vault_path = args.vault or os.path.join(PG_HOME, "vault.json")
    out_path = args.output if args.output is not None else os.path.join(PG_HOME, "evidence.jsonl")
    dest = args.destination or os.path.basename(cmd[0])

    eng = Engine()
    vault = _load_vault(vault_path)
    findings = []

    # 1) redact every argument in place (the prompt usually rides in argv: `claude -p "…"`, `llm "…"`)
    safe_cmd = []
    for a in cmd:
        res = eng.inspect(a, surface="cli", destination=dest, vault=vault)
        safe_cmd.append(res.redacted)
        findings += res.findings

    # 2) redact piped stdin too (`cat secrets.txt | claude`)
    stdin_data = None
    if not sys.stdin.isatty():
        res = eng.inspect(sys.stdin.read(), surface="cli", destination=dest, vault=vault)
        stdin_data, findings = res.redacted, findings + res.findings

    if findings:
        event = build_event(findings, destination=dest, action="redact", surface="cli")
        err(f"🛡  Prompt Guard: redacted {len(findings)} secret/PII span(s) "
            f"[{event['max_severity']}] before calling {cmd[0]} → {dest}")
        if out_path:
            write_event(event, out_path)
        if not vault.is_empty():
            json.dump(vault._to_original, open(vault_path, "w"))

    # 3) run the real LLM CLI; restore placeholders in its output, line by line (near-live)
    proc = subprocess.Popen(
        safe_cmd, text=True, bufsize=1,
        stdin=(subprocess.PIPE if stdin_data is not None else None),
        stdout=subprocess.PIPE, stderr=None)
    if stdin_data is not None:
        try: proc.stdin.write(stdin_data); proc.stdin.close()
        except BrokenPipeError: pass
    for line in proc.stdout:
        sys.stdout.write(vault.restore(line))
        sys.stdout.flush()
    return proc.wait()


_SHELL_SNIPPET = r"""# ── Cataam Prompt Guard — transparent secret redaction for terminal LLMs ──
# Quick guarded one-shot question to any LLM CLI:
ask()  { promptguard wrap -- "$@"; }
# Keep typing `claude` exactly as before — guard engages only for the one-shot/piped
# path (where redaction is reliable); the interactive TUI runs untouched.
claude() {
  if [ -t 0 ] && [[ "$*" != *"-p"* && "$*" != *"--print"* ]]; then
    command claude "$@"
  else
    promptguard wrap --destination claude.ai -- command claude "$@"
  fi
}
# llm / ollama one-shots are always one-shot, so guard them wholesale:
llm()    { promptguard wrap --destination "$1" -- command llm "$@"; }
"""


def cmd_hook(args):
    """Run as a Claude Code UserPromptSubmit hook (reads JSON on stdin; blocks on secret)."""
    from .hook import run_hook
    return run_hook()


def cmd_install_hook(args):
    """Merge the UserPromptSubmit hook into ~/.claude/settings.json."""
    from .hook import install_hook
    return install_hook()


def cmd_install(args):
    """Print a shell snippet that makes guarding invisible — add it to ~/.zshrc (or ~/.bashrc)."""
    sys.stdout.write(_SHELL_SNIPPET)
    err("\n# Add the above to your shell rc, e.g.:\n"
        "#   promptguard install >> ~/.zshrc && source ~/.zshrc\n"
        "# Then just use your LLM normally:  ask 'why does AKIA... 403?'   (secret auto-redacted)")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="promptguard", description="Local-first prompt hygiene for public LLMs.")
    p.add_argument("--version", action="version", version=f"cataam-prompt-guard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--surface", default="cli", help="browser|desktop|ide|cli|proxy")
    common.add_argument("--destination", default="unknown", help="e.g. chat.openai.com")
    common.add_argument("--output", help="append Cataam-importable evidence (JSONL) to this file")

    s = sub.add_parser("scan", parents=[common], help="detect sensitive data (no redaction)")
    s.set_defaults(func=cmd_scan)
    r = sub.add_parser("redact", parents=[common], help="redact reversibly; print safe prompt")
    r.add_argument("--vault", help="write the placeholder->value map for later restore")
    r.set_defaults(func=cmd_redact)
    rs = sub.add_parser("restore", help="re-hydrate a model response using a vault file")
    rs.add_argument("--vault", required=True)
    rs.set_defaults(func=cmd_restore)
    sv = sub.add_parser("serve", parents=[common], help="run the local API for the browser extension")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8765)
    sv.set_defaults(func=cmd_serve)
    pu = sub.add_parser("push", help="push evidence JSONL to a Cataam platform (latches as audit evidence)")
    pu.add_argument("--input", required=True, help="the evidence .jsonl produced by scan/redact/serve")
    pu.add_argument("--url", help="Cataam base URL (or env CATAAM_URL)")
    pu.add_argument("--api-key", help="Cataam org API key, X-API-Key (or env CATAAM_API_KEY)")
    pu.add_argument("--token", help="a logged-in user's JWT, Authorization: Bearer (or env CATAAM_TOKEN)")
    pu.set_defaults(func=cmd_push)

    w = sub.add_parser("wrap", help="transparently guard a downstream LLM CLI (drop-in prefix)")
    w.add_argument("--destination", help="logical destination label for evidence (default: the command name)")
    w.add_argument("--vault", help=f"placeholder→value map (default: {PG_HOME}/vault.json)")
    w.add_argument("--output", help=f"append evidence JSONL (default: {PG_HOME}/evidence.jsonl; '' to disable)")
    w.add_argument("cmd", nargs=argparse.REMAINDER, help="-- <llm-command> [args...]")
    w.set_defaults(func=cmd_wrap)

    ins = sub.add_parser("install", help="print a shell snippet so `claude`/`ask` auto-guard")
    ins.set_defaults(func=cmd_install)

    hk = sub.add_parser("hook", help="run as a Claude Code UserPromptSubmit hook (blocks prompts with secrets)")
    hk.set_defaults(func=cmd_hook)
    ih = sub.add_parser("install-hook", help="wire the block-on-secret hook into ~/.claude/settings.json")
    ih.set_defaults(func=cmd_install_hook)

    args = p.parse_args(argv)
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
