# Prompt Guard — browser extension (alpha reference)

Redacts secrets/keys/PII out of prompts as you submit them to ChatGPT, Claude and Gemini,
by calling the **local** engine on `127.0.0.1:8765`. The prompt is scanned on your own machine.

## Run it
1. Start the local engine: `python3 -m promptguard.cli serve --port 8765 --output evidence.jsonl`
2. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select this `extension/` folder.
3. Open chatgpt.com and submit a prompt containing a fake key (e.g. `AKIAIOSFODNN7EXAMPLE`) — it is
   replaced with a reversible token before sending, and a banner lists what was redacted.

## Status
Alpha reference implementation. Input-box selectors are best-effort per site and need hardening;
native desktop apps, IDE plugins and mobile are **not** covered by a browser extension — see
[../ARCHITECTURE.md](../ARCHITECTURE.md) for the coverage matrix and roadmap. **Fails open** (never
blocks you) if the local engine isn't running.
