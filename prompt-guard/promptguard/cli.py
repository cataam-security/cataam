#!/usr/bin/env python3
"""Prompt Guard CLI.

    promptguard scan    < prompt.txt                 # detect only (exit 1 if sensitive found)
    promptguard redact  < prompt.txt --output ev.json  # redacted prompt to stdout, evidence to JSON
    echo "$RESPONSE" | promptguard restore --vault v.json   # re-hydrate a model response
    promptguard serve   --port 8765                  # local API for the browser extension

Pure stdlib. `pip install rich` for colour (optional).
"""
import argparse
import json
import sys

from . import __version__
from .engine import Engine
from .evidence import write_event

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

    args = p.parse_args(argv)
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
