// Runs in the isolated world of every isolated page. Injects inject.js into the page
// (to hook getUserMedia) and forwards its cam/mic on-off events to the relay's control
// channel. The relay broadcasts them to the host viewer, which then turns the user's
// REAL camera/mic on only while the isolated app is actually using them.
//
// The control-channel host is templated by the entrypoint (RBI_CONTROL_URL) at build/
// run time; falls back to the known VM IP. A content-script WebSocket is NOT subject to
// the page's CSP, so this works even on strict sites like Meet.
(function () {
  var CONTROL_URL = "__RBI_CONTROL_URL__";
  if (CONTROL_URL.indexOf("__RBI") === 0) CONTROL_URL = "wss://172.29.11.239:8443/control?role=pub";

  // inject the main-world hook
  try {
    var s = document.createElement("script");
    s.src = chrome.runtime.getURL("inject.js");
    s.onload = function () { s.remove(); };
    (document.head || document.documentElement).appendChild(s);
  } catch (e) {}

  var ws = null, queue = [];
  function connect() {
    try { ws = new WebSocket(CONTROL_URL); } catch (e) { ws = null; setTimeout(connect, 2000); return; }
    ws.onopen = function () { while (queue.length) ws.send(queue.shift()); };
    ws.onclose = function () { ws = null; setTimeout(connect, 2000); };
    ws.onerror = function () { try { ws.close(); } catch (e) {} };
  }
  connect();

  window.addEventListener("message", function (e) {
    if (e.source !== window || !e.data || e.data.__rbi_media !== 1) return;
    var msg = JSON.stringify({ kind: e.data.kind, on: e.data.on });
    if (ws && ws.readyState === 1) { try { ws.send(msg); } catch (_) {} }
    else queue.push(msg);
  });
})();
