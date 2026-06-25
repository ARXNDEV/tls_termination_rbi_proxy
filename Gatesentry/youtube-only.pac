// Selective RBI routing for your REGULAR browser:
//   ONLY youtube.com (and its subdomains) is sent to the isolation proxy.
//   Everything else — google, gmail, your whole normal browsing, and the
//   omnibox search engine — stays DIRECT and completely untouched.
// This is what lets an isolated YouTube open as a TAB in your normal window
// without affecting any other tab.
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  // Only the MAIN YouTube hostnames are isolated. NOT every *.youtube.com — that
  // wildcard also caught Chrome's prefetch hosts (suggestqueries-clients6.youtube.com,
  // etc.) and spun up stray containers. youtube's own subdomains/CDN are fetched
  // DIRECT by the container, so the client never needs them isolated.
  if (host === "youtube.com" || host === "www.youtube.com" || host === "m.youtube.com"
      || host === "teams.live.com" || host === "teams.microsoft.com"
      || host === "meet.google.com"
      || host === "webcammictest.com" || host === "www.webcammictest.com") {
    return "PROXY 172.29.11.239:8080";
  }
  return "DIRECT";
}
