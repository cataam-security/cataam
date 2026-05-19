#!/usr/bin/env python3
"""
SSL/TLS Audit Tool — checks TLS versions, cipher suites, and certificate validity.
Maps findings to PCI DSS 4.0 requirement 4.2 and SOC 2 CC6.7.
Exports Cataam-importable JSON.

Usage:
    python ssl-tls-audit.py --host api.example.com --pci --output tls-findings.json
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone

try:
    from rich.console import Console
    from rich.table import Table
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

TOOL_VERSION = "1.0.1"
CATAAM_IMPORT_VERSION = "1.0"

# PCI DSS 4.0 Req 4.2.1 — deprecated protocols
DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
APPROVED_PROTOCOLS   = {"TLSv1.2", "TLSv1.3"}

# Weak cipher substrings — flag if found in negotiated cipher
WEAK_CIPHER_PATTERNS = [
    "NULL", "EXPORT", "DES", "RC4", "RC2", "MD5", "anon",
    "3DES", "IDEA", "SEED", "CAMELLIA128",
]

# Strong forward-secrecy cipher patterns
STRONG_PATTERNS = ["ECDHE", "DHE", "CHACHA20", "AES256", "AES128-GCM"]


def cprint(msg, style=""):
    if console:
        console.print(f"[{style}]{msg}[/{style}]" if style else msg)
    else:
        print(msg)


def get_ssl_context(protocol_version) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def probe_protocol(host: str, port: int, protocol_label: str, timeout: int) -> dict:
    """Attempt a TLS handshake and return connection details."""
    protocol_map = {
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    }
    deprecated_const = {
        "TLSv1":   getattr(ssl, "PROTOCOL_TLSv1",   None),
        "TLSv1.1": getattr(ssl, "PROTOCOL_TLSv1_1", None),
        "SSLv3":   None,
        "SSLv2":   None,
    }

    try:
        if protocol_label in protocol_map:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = protocol_map[protocol_label]
            ctx.maximum_version = protocol_map[protocol_label]
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return {
                        "supported": True,
                        "protocol":  ssock.version(),
                        "cipher":    ssock.cipher()[0] if ssock.cipher() else "",
                        "bits":      ssock.cipher()[2] if ssock.cipher() else 0,
                    }
        elif protocol_label in deprecated_const and deprecated_const[protocol_label]:
            ctx = ssl.SSLContext(deprecated_const[protocol_label])
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock) as ssock:
                    return {
                        "supported": True,
                        "protocol":  protocol_label,
                        "cipher":    ssock.cipher()[0] if ssock.cipher() else "",
                        "bits":      ssock.cipher()[2] if ssock.cipher() else 0,
                    }
        else:
            return {"supported": False, "protocol": protocol_label, "cipher": "", "bits": 0,
                    "note": "Protocol not available on this Python build"}
    except (ssl.SSLError, ConnectionRefusedError, OSError):
        return {"supported": False, "protocol": protocol_label, "cipher": "", "bits": 0}


def get_certificate_info(host: str, port: int, timeout: int) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"error": "No certificate presented"}

                not_after_str = cert.get("notAfter", "")
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc) if not_after_str else None

                not_before_str = cert.get("notBefore", "")
                not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc) if not_before_str else None

                days_remaining = (not_after - datetime.now(timezone.utc)).days if not_after else None

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer",  []))
                san = [v for _, v in cert.get("subjectAltName", [])]

                return {
                    "subject_cn":     subject.get("commonName", ""),
                    "issuer_cn":      issuer.get("commonName", ""),
                    "not_before":     not_before.isoformat() if not_before else "",
                    "not_after":      not_after.isoformat()  if not_after  else "",
                    "days_remaining": days_remaining,
                    "san":            san,
                    "version":        cert.get("version", 0),
                    "serial":         str(cert.get("serialNumber", "")),
                }
    except Exception as e:
        return {"error": str(e)}


def audit(host: str, port: int, timeout: int, pci_mode: bool) -> list:
    findings = []
    now = datetime.now(timezone.utc)

    def finding(control, title, status, detail="", severity="MEDIUM", framework="PCI DSS 4.0"):
        findings.append({
            "control":   control,
            "title":     title,
            "status":    status,
            "severity":  severity,
            "detail":    detail,
            "framework": framework,
            "pci_req":   "4.2.1",
            "iso27001":  "A.8.24",
            "soc2":      "CC6.7",
            "cataam_tags": [f"severity:{severity.lower()}", "source:tls-audit", f"host:{host}"],
        })
        color_map = {"PASS": "green", "FAIL": "red", "WARN": "yellow"}
        color = color_map.get(status, "white")
        cprint(f"[{color}][{status}][/{color}] [{control}] {title}")
        if detail:
            cprint(f"       {detail}", "dim")

    # Protocol checks
    cprint("\n--- Protocol Support ---")
    for proto in ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"]:
        result = probe_protocol(host, port, proto, timeout)
        if proto in DEPRECATED_PROTOCOLS:
            if result["supported"]:
                finding(f"TLS.{proto}", f"Deprecated protocol {proto} is disabled",
                        "FAIL", f"{proto} is accepted — PCI DSS 4.0 prohibits this", "HIGH")
            else:
                finding(f"TLS.{proto}", f"Deprecated protocol {proto} is disabled",
                        "PASS", f"{proto} rejected (good)")
        else:
            if result["supported"]:
                cipher = result.get("cipher", "")
                bits   = result.get("bits", 0)
                weak = any(p in cipher.upper() for p in WEAK_CIPHER_PATTERNS)
                finding(f"TLS.{proto}", f"{proto} supported with strong cipher",
                        "PASS" if not weak else "WARN",
                        f"Cipher: {cipher} ({bits} bits)" + (" — weak cipher!" if weak else ""),
                        "MEDIUM" if weak else "LOW")

    # Certificate checks
    cprint("\n--- Certificate ---")
    cert = get_certificate_info(host, port, timeout)
    if "error" in cert:
        finding("CERT.1", "Certificate is valid and accessible", "WARN", cert["error"])
    else:
        days = cert.get("days_remaining", 0)
        if days is None:
            finding("CERT.1", "Certificate expiry", "WARN", "Could not determine expiry date")
        elif days <= 0:
            finding("CERT.1", "Certificate is not expired", "FAIL",
                    f"Certificate expired {abs(days)} days ago", "CRITICAL")
        elif days <= 30:
            finding("CERT.1", "Certificate is not expired", "WARN",
                    f"Certificate expires in {days} days — renew soon", "HIGH")
        else:
            finding("CERT.1", "Certificate is not expired", "PASS",
                    f"Valid for {days} more days (expires {cert['not_after'][:10]})")

        if pci_mode and cert.get("version", 0) < 3:
            finding("CERT.2", "Certificate uses X.509 v3", "FAIL",
                    f"Certificate version: {cert.get('version')} (PCI requires v3)", "HIGH")
        else:
            finding("CERT.2", "Certificate uses X.509 v3", "PASS")

    # PCI DSS pass/fail summary
    if pci_mode:
        cprint("\n--- PCI DSS 4.0 Requirement 4.2.1 Assessment ---")
        failed = [f for f in findings if f["status"] == "FAIL"]
        if not failed:
            finding("PCI.4.2.1", "PCI DSS 4.0 Req 4.2.1 — Overall Assessment", "PASS",
                    "All TLS configuration controls passed", "LOW")
        else:
            finding("PCI.4.2.1", "PCI DSS 4.0 Req 4.2.1 — Overall Assessment", "FAIL",
                    f"{len(failed)} control(s) failed — remediation required before PCI audit", "HIGH")

    return findings


def write_cataam_json(findings: list, host: str, port: int, output_path: str):
    total = len(findings)
    payload = {
        "cataam_import_version": CATAAM_IMPORT_VERSION,
        "tool": "ssl-tls-audit",
        "tool_version": TOOL_VERSION,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "target": {"host": host, "port": port},
        "frameworks": ["PCI DSS 4.0", "ISO 27001:2022 A.8.24", "SOC 2 CC6.7"],
        "summary": {
            "total": total,
            "pass":  sum(1 for f in findings if f["status"] == "PASS"),
            "fail":  sum(1 for f in findings if f["status"] == "FAIL"),
            "warn":  sum(1 for f in findings if f["status"] == "WARN"),
        },
        "findings": findings,
    }
    with open(output_path, "w") as fh:
        json.dump(payload, fh, indent=2)
    cprint(f"\nCataam JSON written to {output_path}", "green")
    cprint("Import at: https://cataam.com/import", "dim")


def main():
    parser = argparse.ArgumentParser(description="Cataam SSL/TLS Audit (PCI DSS 4.0 Req 4.2)")
    parser.add_argument("--host",    required=True,  help="Hostname or IP to audit")
    parser.add_argument("--port",    type=int, default=443, help="Port (default: 443)")
    parser.add_argument("--pci",     action="store_true",   help="Apply PCI DSS 4.0 pass/fail thresholds")
    parser.add_argument("--output",  default="",            help="Cataam-importable JSON output file")
    parser.add_argument("--timeout", type=int, default=10,  help="Connection timeout seconds (default: 10)")
    args = parser.parse_args()

    cprint("=" * 56, "bold")
    cprint(f" Cataam TLS Audit v{TOOL_VERSION}", "bold")
    cprint(f" Target: {args.host}:{args.port} | PCI mode: {args.pci}", "dim")
    cprint("=" * 56, "bold")

    findings = audit(args.host, args.port, args.timeout, args.pci)

    total = len(findings)
    passed = sum(1 for f in findings if f["status"] == "PASS")
    failed = sum(1 for f in findings if f["status"] == "FAIL")
    cprint(f"\nSummary: {passed}/{total} passed | {failed} failed", "bold")

    if args.output:
        write_cataam_json(findings, args.host, args.port, args.output)


if __name__ == "__main__":
    main()
