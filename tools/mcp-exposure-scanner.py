#!/usr/bin/env python3
"""MCP Exposure Scanner — Cataam open-source security tooling.

Finds INTERNET-REACHABLE Model Context Protocol (MCP) servers and checks three
posture issues behind the July-2026 MCP vulnerability wave. MCP servers are the
middleware that let an AI model call real tools; they are meant to run on
loopback for a LOCAL client, so an externally-reachable one is "shadow AI
infrastructure" — a privileged, tool-wielding endpoint with no front door.

DEFENSIVE / READ-ONLY. This scanner only speaks the MCP `initialize` handshake
and the read-only `tools/list` method. It NEVER calls `tools/call` (no tool is
ever executed) and sends no exploit payloads. Run it against systems you are
authorized to test.

Checks (each maps to SOC 2 / ISO 27001 / ISO 42001 controls):
  1. EXPOSED            an MCP server completes the handshake from outside the host
  2. UNAUTH-DISCLOSURE  `tools/list` answers with no credentials (capability leak)
  3. ORIGIN-UNVALIDATED a foreign Origin is accepted (DNS-rebinding / CSRF)

Related advisories: MCP Python SDK CVE-2026-59950 (Host/Origin), CVE-2026-52869
(unverified sessions), CVE-2026-52870; meta-ads-mcp CVE-2026-54547/-54549;
LangBot CVE-2026-54449; ToolHive CVE-2026-58196.

Usage:
  python mcp-exposure-scanner.py --target host-or-url --authorized
  python mcp-exposure-scanner.py --target 10.0.0.5 --port 8080 --authorized --output json

No third-party dependencies — Python 3.8+ standard library only.

MIT License · https://cataam.com
"""
import argparse
import json
import ssl
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

TOOL_VERSION = "1.0.0"

META = {
    "NAME": "MCP (Model Context Protocol) attack-surface exposure",
    "ADVISORIES": ["CVE-2026-59950", "CVE-2026-52869", "CVE-2026-52870",
                   "CVE-2026-54547", "CVE-2026-54549", "CVE-2026-54449", "CVE-2026-58196"],
    "SOC2": "CC6.1 Logical access; CC6.6 Boundary protection — restrict access to protected assets and defend the system boundary.",
    "ISO27001": "A.8.8 Management of technical vulnerabilities; A.8.23 Web/network service filtering.",
    "ISO42001": "A.6.2.4 AI system operation & monitoring — an AI tool-server is a governed AI asset, not an unmanaged library.",
    "REMEDIATION": [
        "Bind the MCP server to 127.0.0.1; never expose it directly to the internet.",
        "Front it with an authenticating reverse proxy if remote access is required.",
        "Enforce an Origin/Host allow-list (reject unknown Origins with 403).",
        "Require a per-session token for every method beyond `initialize`.",
        "Update the MCP SDK/server past the July-2026 advisories; remove exec/file/HTTP tools from any exposed server.",
    ],
}

# MCP transports in the wild: Streamable-HTTP (/mcp), legacy HTTP+SSE (/sse, /message).
MCP_PATHS = ["/mcp", "/sse", "/message", "/mcp/sse", "/rpc", "/"]
# Tool names that make an *unauthenticated* server materially worse (SSRF / RCE / data reach).
DANGEROUS = ("exec", "shell", "command", "run", "eval", "python", "sql", "query",
             "file", "read", "write", "delete", "fetch", "http", "request", "url", "browse")
_UA = "cataam-mcp-scanner/%s" % TOOL_VERSION
_CTX = ssl._create_unverified_context()  # internal MCP servers commonly use self-signed certs


def _rpc(url, method, params, origin=None, timeout=6.0):
    """Send one JSON-RPC call (read-only). Returns (status, parsed_json_or_None, headers)."""
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    headers = {"Content-Type": "application/json", "User-Agent": _UA,
               "Accept": "application/json, text/event-stream"}
    if origin:
        headers["Origin"] = origin
    req = Request(url, data=payload, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=timeout, context=_CTX) as r:
            return getattr(r, "status", 200), _parse(r.read()), dict(r.headers)
    except HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        return e.code, _parse(body), dict(e.headers or {})
    except (URLError, OSError, ValueError):
        return None, None, {}


def _parse(raw):
    """Parse a JSON body, or the `data:` frame of an SSE response."""
    try:
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    except Exception:
        return None
    try:
        return json.loads(text)
    except Exception:
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except Exception:
                    continue
    return None


def _is_mcp(body):
    """A response is MCP iff it is JSON-RPC 2.0 whose result carries the handshake shape."""
    if isinstance(body, dict) and body.get("jsonrpc") == "2.0":
        res = body.get("result") or {}
        return any(k in res for k in ("protocolVersion", "serverInfo", "capabilities"))
    return False


def _initialize(url, origin=None, timeout=6.0):
    return _rpc(url, "initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "cataam-mcp-scanner", "version": TOOL_VERSION},
    }, origin=origin, timeout=timeout)


def _bases(target, port):
    t = target.strip()
    if t.startswith(("http://", "https://")):
        return [t.rstrip("/")]
    p = ":%d" % port if port else ""
    return ["https://%s%s" % (t, p), "http://%s%s" % (t, p)]


def scan(target, port=None, timeout=6.0):
    """Read-only MCP posture scan. Returns a structured result dict."""
    result = {"target": target, "mcp_detected": False, "endpoint": None,
              "server": {}, "findings": [], "checked_paths": []}
    for base in _bases(target, port):
        for path in MCP_PATHS:
            url = base + path
            status, body, headers = _initialize(url, timeout=timeout)
            result["checked_paths"].append(url)
            if not _is_mcp(body):
                continue

            # ── MCP server confirmed on the wire ──
            result["mcp_detected"] = True
            result["endpoint"] = url
            result["server"] = (body.get("result") or {}).get("serverInfo") or {}

            # 1) EXPOSED (it answered from outside the host at all)
            result["findings"].append({
                "id": "MCP-SERVER-EXPOSED", "severity": "HIGH",
                "detail": "An MCP server completed the handshake at %s. MCP servers should bind to loopback; external reachability is the exposure." % url,
            })

            # 2) UNAUTHENTICATED CAPABILITY DISCLOSURE
            t_status, t_body, _ = _rpc(url, "tools/list", {}, timeout=timeout)
            tools = ((t_body or {}).get("result") or {}).get("tools") if isinstance(t_body, dict) else None
            if isinstance(tools, list):
                names = [str(t.get("name", "")) for t in tools if isinstance(t, dict)]
                dangerous = sorted({n for n in names for d in DANGEROUS if d in n.lower()})
                result["findings"].append({
                    "id": "MCP-UNAUTH-CAPABILITY-DISCLOSURE",
                    "severity": "HIGH" if dangerous else "MEDIUM",
                    "detail": "tools/list returned %d tools with no credentials." % len(names)
                              + (" Execution/SSRF-capable tools exposed: %s." % ", ".join(dangerous[:8]) if dangerous else ""),
                    "tools": names[:25], "dangerous_tools": dangerous,
                })

            # 3) ORIGIN NOT VALIDATED (DNS rebinding / CSRF)
            o_status, o_body, _ = _initialize(url, origin="https://cataam-mcp-probe.invalid", timeout=timeout)
            if _is_mcp(o_body) and o_status not in (401, 403):
                result["findings"].append({
                    "id": "MCP-ORIGIN-NOT-VALIDATED", "severity": "MEDIUM",
                    "detail": "The server accepted a foreign Origin (https://cataam-mcp-probe.invalid); "
                              "it does not validate Origin/Host and is exposed to DNS-rebinding / CSRF (CVE-2026-59950 class).",
                })
            return result
    return result


def print_text(res):
    print("── Cataam MCP Exposure Scanner v%s ──────────────────────────────" % TOOL_VERSION)
    print("Target: %s" % res["target"])
    if not res["mcp_detected"]:
        print("Result: no MCP server detected on the probed endpoints.")
        print("        (checked: %s)" % ", ".join(p.rsplit("/", 1)[-1] or "/" for p in MCP_PATHS))
        return
    srv = res["server"]
    print("Result: MCP server DETECTED at %s" % res["endpoint"])
    if srv:
        print("Server: %s %s" % (srv.get("name", "unknown"), srv.get("version", "")))
    print("\nFindings (%d):" % len(res["findings"]))
    for f in res["findings"]:
        print("  [%-6s] %s" % (f["severity"], f["id"]))
        print("           %s" % f["detail"])
    print("\nRemediation:")
    for step in META["REMEDIATION"]:
        print("  - %s" % step)
    print("\nCompliance mapping:")
    print("  SOC 2      %s" % META["SOC2"])
    print("  ISO 27001  %s" % META["ISO27001"])
    print("  ISO 42001  %s" % META["ISO42001"])
    print("\nRelated advisories: %s" % ", ".join(META["ADVISORIES"]))


def main():
    ap = argparse.ArgumentParser(description="Read-only scanner for exposed MCP (AI tool) servers.")
    ap.add_argument("--target", required=True, help="host, ip, or full URL to scan")
    ap.add_argument("--port", type=int, default=None, help="port (if --target is a bare host)")
    ap.add_argument("--timeout", type=float, default=6.0, help="per-request timeout seconds (default 6)")
    ap.add_argument("--output", choices=["text", "json"], default="text")
    ap.add_argument("--authorized", action="store_true",
                    help="confirm you are authorized to scan this target (required)")
    args = ap.parse_args()

    if not args.authorized:
        sys.stderr.write("Refusing to scan without --authorized. Only scan systems you are permitted to test.\n")
        sys.exit(2)

    res = scan(args.target, port=args.port, timeout=args.timeout)
    if args.output == "json":
        print(json.dumps({"tool": "mcp-exposure-scanner", "version": TOOL_VERSION,
                          "compliance": {"soc2": META["SOC2"], "iso27001": META["ISO27001"],
                                         "iso42001": META["ISO42001"]},
                          "advisories": META["ADVISORIES"], **res}, indent=2))
    else:
        print_text(res)
    # exit 1 if anything was flagged, 0 if clean — CI-friendly
    sys.exit(1 if res["findings"] else 0)


if __name__ == "__main__":
    main()
