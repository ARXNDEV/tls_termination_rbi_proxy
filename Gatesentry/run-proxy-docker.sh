#!/usr/bin/env bash
# Run the whole Gatesentry TLS-termination + RBI proxy in Docker.
# The proxy launches per-session RBI containers on the host via docker.sock and
# reverse-proxies each isolated site through its own connection, so the client's
# URL bar stays the real site (e.g. youtube.com) with no localhost.
set -euo pipefail
cd "$(dirname "$0")"

IMG=gatesentry-proxy:latest

echo "==> building proxy image"
docker build -f Dockerfile.proxy -t "$IMG" .

echo "==> (re)starting proxy container"
docker rm -f gatesentry-proxy >/dev/null 2>&1 || true
docker run -d --name gatesentry-proxy \
  -p 8080:8080 -p 8001:8001 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/config.json:/app/config.json:ro" \
  -e RBI_FORWARD_HOST=host.docker.internal \
  -e RBI_IMAGE=rbi-chrome-neko:latest \
  -e RBI_PROXY_DEMO_DIRECT=1 \
  --add-host=host.docker.internal:host-gateway \
  "$IMG"

echo "==> proxy up on :8080 (proxy) / :8001 (PAC)"
echo "    point the browser at 127.0.0.1:8080, trust rbi-ca.cert.pem, then open any https site."
echo "    On a production x86-64 host, set RBI_PROXY_DEMO_DIRECT=0 to keep the full firewall + egress proxy."
