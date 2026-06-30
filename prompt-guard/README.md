<p align="center">
  <a href="https://cataam.com">
    <img src="../assets/logo.svg" alt="Cataam" height="50" />
  </a>
</p>

# Prompt Guard — local-first prompt hygiene for public LLMs

[![Maintained by Cataam](https://img.shields.io/badge/Maintained%20by-Cataam-3b82f6?style=flat-square)](https://cataam.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](../LICENSE)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange?style=flat-square)](./ARCHITECTURE.md)

Employees paste code, API keys, passwords and customer data into ChatGPT, Claude, Copilot and Gemini every day — and it leaves the corporate boundary into models you don't control. Samsung banned ChatGPT in 2023 after engineers pasted source code; today **~35% of all data put into AI tools is sensitive, and source code is the #1 leaked category** (Cyberhaven).

**Prompt Guard sifts secrets, keys and PII out of a prompt _before it leaves the machine_ — reversibly, so the answer stays useful — and writes an audit-evidence record mapped to ISO 42001 / NIST AI RMF / EU AI Act.**

It is **local-first** (the prompt is scanned on your laptop; nothing is sent anywhere for the scan), **open** (you can read every detection rule), and **dependency-free** at the core (Python 3.8+ stdlib).

---

## Why this one is different

| Most tools | Prompt Guard |
|---|---|
| Network proxy / SaaS — the prompt goes *to the vendor* to be inspected | **On-device** — the prompt never leaves the machine for scanning |
| Closed detection logic (black box) | **Open, inspectable rule packs** — fork & tune them |
| Block or warn | **Reversible redaction** — strip the secret, send the prompt, re-hydrate the answer |
| Audit log | **Auditor-ready evidence** mapped to AI controls (the EU AI Act asks for exactly this) |
| Enterprise sales-gated | **Free, MIT, runs on a laptop** |

> Architecture, threat model and the honest coverage limits: see **[ARCHITECTURE.md](./ARCHITECTURE.md)**.

---

## Quick start — guard your terminal LLM in one line

You already ask LLMs from your terminal. Put `promptguard wrap --` in front and **nothing else changes** — you type your question once, normally. The secret is stripped on the way out and the answer is re-hydrated on the way back:

```bash
promptguard wrap -- claude -p "my deploy 403s with AKIAIOSFODNN7EXAMPLE, why?"
#  🛡  Prompt Guard: redacted 1 secret/PII span(s) [CRITICAL] before calling claude → claude.ai
#  the model receives:  "...403s with «PG:AWS_ACCESS_KEY_ID:1», why?"   ← secret never leaves
#  you see the answer:  "...rotate AKIAIOSFODNN7EXAMPLE..."             ← de-tokenized locally
```

It redacts secrets in the **arguments and any piped stdin**, works with **any** CLI (`claude`, `llm`, `ollama run`, …), and auto-writes audit evidence to `~/.promptguard/evidence.jsonl`.

### Make it invisible

```bash
promptguard install >> ~/.zshrc && source ~/.zshrc
```

Now keep typing `claude` exactly as before (the guard engages only on the one-shot/`-p`/piped path, where redaction is reliable; the interactive TUI runs untouched), or use the drop-in `ask`:

```bash
ask claude -p "rotate AKIAIOSFODNN7EXAMPLE for me"   # auto-guarded
```

> Fully-interactive TUI chat (keystroke-level) is covered by the **[browser extension](./extension/)** and the planned endpoint agent — see [ARCHITECTURE.md](./ARCHITECTURE.md). The terminal wrapper covers the one-shot/piped path, which is where pasted secrets actually leak.

<details><summary>Lower-level commands (scan / redact / restore / serve)</summary>

```bash
cd prompt-guard
echo 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' | python3 -m promptguard.cli scan
echo 'my key is AKIAIOSFODNN7EXAMPLE, why 403?' | python3 -m promptguard.cli redact --vault vault.json --output evidence.jsonl
echo 'rotate «PG:AWS_ACCESS_KEY_ID:1» now'       | python3 -m promptguard.cli restore --vault vault.json
python3 -m promptguard.cli serve --port 8765 --output evidence.jsonl   # local API for the browser extension
```
</details>

---

## Compliance mapping (the evidence)

Every redaction emits a Cataam-importable `ai_egress_control` event mapping the prevented leak to:

| Framework | Example controls |
|---|---|
| **ISO/IEC 42001:2023** (AI management) | A.6.2.4, A.7.4, B.6.2 |
| **NIST AI RMF + GenAI Profile** | MAP 4.1, MEASURE 2.10, MANAGE 2.2 |
| **EU AI Act** | Art.10 (data governance), **Art.12 (logging)** |
| **ISO 27001:2022** | A.8.12 (data leakage prevention), A.5.34 (PII) |
| **SOC 2** | CC6.7 |

The event carries only **non-sensitive previews** (`AKI…LE (20 chars)`) — never the raw secret. Stream the JSONL into your SIEM, or push it to the [Cataam](https://cataam.com) platform — it latches each event as **auditor-ready evidence** for the *"AI prompt/data egress to public LLMs is controlled"* control (ISO 42001 A.6.2.8 / A.9.2, NIST GAI-4, EU AI Act Art.12):

```bash
export CATAAM_URL=https://app.yourorg.cataam.com CATAAM_API_KEY=...
python3 -m promptguard.cli push --input evidence.jsonl
#  -> {"ingested": 12, "total": 12}   (now visible under AI Governance → Continuous Monitoring)
```

---

## Contributing — detection rules are the flywheel

The highest-leverage contribution is **detection rules**. Add a pattern to [`promptguard/rules.json`](./promptguard/rules.json) — no code changes needed — and a test case. New secret formats, regional PII, and framework-mapping refinements are all welcome. See [ARCHITECTURE.md → Rule packs](./ARCHITECTURE.md#rule-packs) and the repo [CONTRIBUTING.md](../CONTRIBUTING.md).

```bash
python3 tests/test_promptguard.py     # run the tests
```

---

## Honest scope (alpha)

Prompt Guard v0 is the **engine + CLI + local API + a browser-extension reference**. No single tool covers every surface — browser extensions miss native desktop apps and IDEs; nothing covers personal phones. The roadmap (endpoint agent for desktop/IDE coverage, Presidio NER for richer PII, a sanctioned-AI gateway) and the deliberate coverage limits are documented in **[ARCHITECTURE.md](./ARCHITECTURE.md)**. We'd rather be precise about what we cover than claim "100%."

---

<sub>Part of the [Cataam open-source security toolkit](../README.md). Cataam is a commercial GRC, iASM & BAS platform — this tool is free and standalone.</sub>
