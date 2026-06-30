// Tracks how many items Prompt Guard has redacted this session (shown on the toolbar badge).
let count = 0;
chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.type === "pg_event" && msg.event) {
    count += (msg.event.finding_count || 0);
    chrome.action.setBadgeText({ text: String(count) });
    chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
    chrome.storage.session.set({ lastEvent: msg.event, total: count });
  }
});
