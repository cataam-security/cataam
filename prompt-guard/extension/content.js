/*
 * Cataam Prompt Guard — content script (alpha reference).
 *
 * Intercepts the moment a prompt is about to be sent to a public LLM (Enter / Send / paste),
 * sends the text to the LOCAL engine on 127.0.0.1:8765 for on-device redaction, and rewrites the
 * input box with the safe (reversibly-tokenized) text before it leaves the browser. The original
 * prompt never goes anywhere except your own machine.
 *
 * NOTE (alpha): each LLM site is a different React app, so the input selectors below are best-effort
 * and will need per-site hardening. This is a reference implementation, not production coverage.
 * See ../ARCHITECTURE.md for the surface-coverage limits and roadmap.
 */
const ENGINE = "http://127.0.0.1:8765";

const SELECTORS = [
  "#prompt-textarea",                        // ChatGPT
  'div[contenteditable="true"]',             // ChatGPT / Claude / Gemini (contenteditable)
  'textarea[placeholder]',                   // generic fallback
];

function findInput() {
  for (const sel of SELECTORS) {
    const el = document.querySelector(sel);
    if (el) return el;
  }
  return null;
}

function getText(el) {
  return el.value !== undefined ? el.value : el.innerText;
}
function setText(el, text) {
  if (el.value !== undefined) {
    el.value = text;
    el.dispatchEvent(new Event("input", { bubbles: true }));
  } else {
    el.innerText = text;
    el.dispatchEvent(new InputEvent("input", { bubbles: true }));
  }
}

async function inspect(text) {
  const r = await fetch(`${ENGINE}/inspect`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, destination: location.hostname, surface: "browser" }),
  });
  return r.json();
}

function banner(findings) {
  let b = document.getElementById("cataam-pg-banner");
  if (!b) {
    b = document.createElement("div");
    b.id = "cataam-pg-banner";
    b.style = "position:fixed;bottom:16px;right:16px;z-index:2147483647;max-width:360px;" +
      "background:#0f172a;color:#fff;border-left:4px solid #f59e0b;border-radius:10px;" +
      "padding:12px 14px;font:13px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;box-shadow:0 6px 24px rgba(0,0,0,.3)";
    document.body.appendChild(b);
  }
  const items = findings.map(f => `• ${f.label} <span style="opacity:.6">(${f.severity})</span>`).join("<br>");
  b.innerHTML = `<b>Prompt Guard redacted ${findings.length} item(s)</b><br>` +
    `<span style="opacity:.85">${items}</span><br>` +
    `<span style="opacity:.6;font-size:11px">Secrets replaced with reversible tokens before sending. The answer is re-hydrated locally.</span>`;
  clearTimeout(b._t); b._t = setTimeout(() => b.remove(), 6000);
}

// keep the latest vault so we can re-hydrate the model's streamed answer locally
let LAST_VAULT = {};

async function guard(el) {
  const text = getText(el);
  if (!text || !text.trim()) return true;
  try {
    const res = await inspect(text);
    if (res.clean) return true;
    setText(el, res.redacted);          // rewrite the box with the safe prompt
    LAST_VAULT = Object.assign(LAST_VAULT, res.vault);
    banner(res.findings);
    chrome.runtime.sendMessage({ type: "pg_event", event: res.event }).catch(() => {});
    return true;
  } catch (e) {
    // engine not running → fail OPEN with a visible warning (do not silently block the user)
    console.warn("[Prompt Guard] local engine unreachable — start `promptguard serve`.", e);
    return true;
  }
}

// Intercept Enter-to-send (capture phase, before the site handles it)
document.addEventListener("keydown", async (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    const el = findInput();
    if (el && (e.target === el || el.contains(e.target))) {
      e.stopImmediatePropagation();
      e.preventDefault();
      await guard(el);
      // re-dispatch a clean Enter so the site sends the now-redacted text
      el.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    }
  }
}, true);

// Intercept the Send button (best-effort)
document.addEventListener("click", async (e) => {
  const btn = e.target.closest('button[data-testid="send-button"], button[aria-label*="Send" i]');
  if (btn) {
    const el = findInput();
    if (el) { e.stopImmediatePropagation(); e.preventDefault(); await guard(el); btn.click(); }
  }
}, true);

console.log("[Cataam Prompt Guard] active on", location.hostname, "— engine:", ENGINE);
