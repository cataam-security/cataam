const E = "http://127.0.0.1:8765/healthz";
fetch(E).then(r => r.json()).then(j => {
  document.getElementById("engine").innerHTML =
    `<span class="dot ok"></span>v${j.version}`;
}).catch(() => {
  document.getElementById("engine").innerHTML =
    `<span class="dot bad"></span>not running`;
});
chrome.storage.session.get(["total"]).then(s => {
  document.getElementById("count").textContent = s.total || 0;
});
