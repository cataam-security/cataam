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

## Quick start

```bash
# no install needed — pure stdlib core
cd prompt-guard

# 1) scan a prompt (exit 1 if sensitive data found)
echo 'deploy fails: AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' \
  | python3 -m promptguard.cli scan

# 2) redact reversibly — the safe prompt is printed; secrets go to a local vault
echo 'my key is AKIAIOSFODNN7EXAMPLE, why 403?' \
  | python3 -m promptguard.cli redact --vault vault.json --output evidence.jsonl
#  -> my key is «PG:AWS_ACCESS_KEY_ID:1», why 403?

# 3) re-hydrate the model's answer locally
echo 'rotate «PG:AWS_ACCESS_KEY_ID:1» now' | python3 -m promptguard.cli restore --vault vault.json

# 4) run the local API the browser extension talks to (loopback only)
python3 -m promptguard.cli serve --port 8765 --output evidence.jsonl
```

Then load the **[browser extension](./extension/)** unpacked (`chrome://extensions` → *Load unpacked*) to redact pastes into ChatGPT/Claude/Gemini automatically.

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
