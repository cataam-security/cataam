# Prompt Guard — Architecture, Threat Model & Roadmap

## Design principles
1. **Local-first.** Detection runs on the device. The prompt text is never sent anywhere for the
   scan itself — the engine binds `127.0.0.1` only and refuses non-loopback hosts.
2. **Open & inspectable.** Every detection rule is plain JSON you can read, fork and tune. A tool
   that sees all of an employee's prompts must be auditable — closed "privacy" extensions have been
   caught exfiltrating ChatGPT/Claude chats, so transparency is the trust model.
3. **Reversible, not destructive.** Redaction replaces a secret with a stable placeholder and keeps
   the mapping locally, so the model's answer is re-hydrated and the user still gets a useful reply.
   That keeps false positives cheap and prevents the "users route around it" failure mode.
4. **Evidence, not just logs.** Each redaction is a structured event mapped to AI-governance controls
   (ISO 42001 / NIST AI RMF / EU AI Act Art. 12) — the artifact auditors and regulators ask for.
5. **Fail open.** If the engine is down or unsure, never block the human — warn instead. Security
   that breaks work gets uninstalled.

## Components
```
            ┌──────────────────────────── interception (any one) ────────────────────────────┐
            │  browser extension      CLI / shell pipe       (roadmap) endpoint agent · IDE     │
            └───────────────────────────────────┬────────────────────────────────────────────┘
                                                 │  POST /inspect  (loopback only)
                                   ┌─────────────▼──────────────┐
                                   │        engine.py            │  on-device, stdlib only
                                   │  detect → redact → evidence │
                                   └───┬─────────┬─────────┬─────┘
                       detectors.py ───┘         │         └─── evidence.py ── Cataam-importable
                       + rules.json (regex/      │              + controls.json  JSONL (→ SIEM /
                        entropy/Luhn)       vault.py (reversible       Cataam GRC latch)
                                            tokenization, local)
```
- **`detectors.py` + `rules.json`** — regex, Shannon-entropy and Luhn detection. Rules are data, so
  contributors extend coverage without touching code.
- **`vault.py`** — bidirectional placeholder↔value map (session-scoped, in-memory by default).
- **`evidence.py` + `controls.json`** — builds the `ai_egress_control` event and maps finding
  categories → framework controls. Events carry **previews only**, never the raw secret.
- **`engine.py`** — orchestrates inspect (detect→redact→evidence) and restore.
- **`cli.py`** — `scan` / `redact` / `restore` / `serve`.
- **`server.py`** — loopback HTTP API for the extension/IDE; pure stdlib.
- **`extension/`** — MV3 browser reference that redacts on submit.

## Rule packs
A rule in `rules.json`:
```json
{"id":"github-token","label":"GitHub Token","category":"secret","severity":"CRITICAL",
 "pattern":"\\b(?:ghp|gho|...)_[A-Za-z0-9_]{36,255}\\b"}
```
- `category` ∈ `secret | pii | code` (drives the control mapping in `controls.json`).
- A `pattern` with a capture group redacts only the group (e.g. the value in `password=...`).
- `"luhn": true` post-validates numeric matches (cards). `"entropy": {...}` flags high-entropy tokens.
- Add a matching assertion in `tests/test_promptguard.py`. PRs that add a real-world secret format
  (with a synthetic example) or regional PII are the most valuable contribution.

## Threat model
**Protects against:** an authenticated employee inadvertently pasting/typing secrets, keys or PII
into a public LLM through a covered surface. Reduces blast radius and produces governance evidence.

**Explicitly does NOT (and cannot fully) cover — we state this plainly:**

| Surface | Browser ext | CLI/pipe | Endpoint agent (roadmap) |
|---|---|---|---|
| LLM in a browser tab | ✅ | — | ✅ (managed) |
| Native desktop app (ChatGPT/Claude desktop, cert-pinned) | ❌ | — | ✅ (managed) |
| IDE plugin (Copilot/Cursor) | ❌ | ✅ if piped | ✅ (managed) |
| Personal device / BYOD / phone | ❌ | ❌ | ❌ |

The largest real-world leakage (~47–74% of GenAI use is on personal accounts/BYOD) is unreachable by
*any* technical control and is addressed only by policy, culture, and offering a sanctioned AI path.
Prompt Guard's honest promise is **"maximal coverage on the surfaces you run it on, plus evidence,"**
not "100%." It is also not a defense against a *malicious* insider deliberately exfiltrating data.

**The tool's own trust posture:** no prompt leaves the machine for scanning; loopback-only bind;
no telemetry; MIT and fully readable. A vulnerability in something that brokers every prompt would be
severe — see [../SECURITY.md](../SECURITY.md) for disclosure.

## Roadmap
- **v0 (here):** engine + rule packs + CLI + local API + browser-extension reference + evidence.
- **v0.2:** optional [Presidio](https://github.com/microsoft/presidio) NER for richer PII; per-site
  extension hardening; `restore` wired into the extension to re-hydrate streamed answers.
- **v0.3:** **endpoint agent** (clipboard/process-layer) to cover native desktop apps + IDEs — the
  only model that survives cert-pinning; policy file; encrypted on-disk vault.
- **v0.4:** **sanctioned-AI gateway** mode (govern approved API traffic) so employees have a compliant
  path; org policy + allow/deny lists.
- **Cataam integration:** one-click import of the evidence JSONL to latch `ai_egress_control` events
  as audit evidence against an ISO 42001 / NIST AI RMF control in the Cataam platform.
