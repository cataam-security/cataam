"""Local, loopback-only HTTP API that the browser extension / IDE plugin call to redact a
prompt before it is sent to a public LLM. Pure stdlib. Binds 127.0.0.1 only — the prompt
text never leaves the machine.

  POST /inspect  {"text": "...", "destination": "chat.openai.com", "surface": "browser"}
       -> {"clean": false, "redacted": "...", "findings": [...], "event": {...}, "vault": {...}}
  POST /restore  {"text": "...with placeholders", "vault": {"«PG:...»": "secret"}}
       -> {"text": "...re-hydrated..."}
  GET  /healthz  -> {"status":"ok","version":"..."}
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .engine import Engine
from .evidence import write_event
from .vault import Vault

_ENGINE = Engine()
_EVIDENCE_LOG = None

# Only browser extensions (chrome-extension://, moz-extension://) and the LLM sites' own origins
# are meaningful callers; we keep CORS permissive for localhost dev but the bind is loopback-only.
_CORS = {"Access-Control-Allow-Origin": "*",
         "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
         "Access-Control-Allow-Headers": "Content-Type"}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in _CORS.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in _CORS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"status": "ok", "tool": "cataam-prompt-guard", "version": __version__})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, {"error": "invalid JSON"})

        if self.path == "/inspect":
            res = _ENGINE.inspect(data.get("text", ""),
                                  destination=data.get("destination", "unknown"),
                                  surface=data.get("surface", "browser"),
                                  actor=data.get("actor"))
            if _EVIDENCE_LOG and res.findings:
                write_event(res.event, _EVIDENCE_LOG)
            return self._send(200, {
                "clean": res.clean,
                "redacted": res.redacted,
                "findings": [f.to_dict() for f in res.findings],
                "event": res.event,
                "vault": res.vault._to_original,   # caller keeps this to restore the response locally
            })
        if self.path == "/restore":
            v = Vault(); v._to_original = data.get("vault", {})
            return self._send(200, {"text": v.restore(data.get("text", ""))})
        self._send(404, {"error": "not found"})

    def log_message(self, *a):   # quiet by default
        pass


def serve(host="127.0.0.1", port=8765, evidence_log=None):
    global _EVIDENCE_LOG
    _EVIDENCE_LOG = evidence_log
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("refusing to bind a non-loopback host — Prompt Guard is local-first by design")
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"cataam-prompt-guard {__version__} listening on http://{host}:{port}  (loopback only)")
    if evidence_log:
        print(f"audit evidence -> {evidence_log}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
