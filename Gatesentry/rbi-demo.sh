#!/usr/bin/env bash
#
# RBI demo — drive a request through the gatesentry proxy into the selkies
# isolated browser, then prove the real site was rendered *inside* the
# container (never on the client). Run it yourself and inspect the artifacts.
#
#   ./rbi-demo.sh [url]
#
# Default url: the Wikipedia "Remote browser isolation" page.
set -uo pipefail

URL="${1:-https://en.wikipedia.org/wiki/Remote_browser_isolation}"
DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="/Users/arun/Downloads/neko-master 2/docker-compose.yaml"
CONTAINER="neko-master2-firefox-1"
SHOT="$DIR/rbi-demo-screenshot.png"

note() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

note "1/4  Selkies isolated-browser container"
docker compose -f "$COMPOSE" up -d firefox >/dev/null 2>&1
code=000
for _ in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/ 2>/dev/null || echo 000)
  [ "$code" = "200" ] && break
  sleep 1
done
echo "    selkies viewer  http://127.0.0.1:8081  ->  HTTP $code"
[ "$code" = "200" ] || { echo "    selkies not serving; check: docker logs $CONTAINER"; exit 1; }

note "2/4  Gatesentry TLS-termination proxy"
if ! pgrep -f gatesentrybin >/dev/null 2>&1; then
  [ -x "$DIR/bin/gatesentrybin" ] || (cd "$DIR" && go build -o bin/gatesentrybin .)
  (cd "$DIR" && nohup ./bin/gatesentrybin config.json >/tmp/gatesentry.log 2>&1 &)
  sleep 4
fi
lsof -nP -iTCP:8080 -sTCP:LISTEN 2>/dev/null | grep -q gatesentr \
  && echo "    proxy listening on :8080" \
  || { echo "    proxy failed to start; see /tmp/gatesentry.log"; exit 1; }

note "3/4  Drive the RBI loop through the proxy  ->  $URL"
pcode=$(curl -sk -x http://127.0.0.1:8080 -o /dev/null -w '%{http_code}' "$URL" --max-time 30)
echo "    proxy returned HTTP $pcode  (the selkies viewer page; isolation triggered)"
echo "    waiting for the isolated Firefox to render..."
sleep 10

note "4/4  Capture the isolated browser's actual screen (display :20)"
docker exec -u ubuntu -e DISPLAY=:20 "$CONTAINER" xwd -root -silent -out /tmp/shot.xwd
docker cp "$CONTAINER":/tmp/shot.xwd /tmp/shot.xwd >/dev/null
ffmpeg -y -loglevel error -i /tmp/shot.xwd "$SHOT"
echo "    saved screenshot: $SHOT"

cat <<EOF

------------------------------------------------------------------
DONE — verify it yourself:

  1. Open the screenshot the isolated browser just produced:
        open "$SHOT"
     You should see "$URL" rendered inside the isolated Google
     Chrome in KIOSK mode — no tabs, no address bar, only this URL.

  2. Live, interactive view — open in your own browser:
        http://127.0.0.1:8081
     The selkies WebRTC viewer streaming that kiosk Chrome.

  3. Full product flow — drive it from YOUR Mac Chrome via the proxy
     (after trusting the CA once, see README/notes):
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \\
          --proxy-server="http://127.0.0.1:8080" \\
          --user-data-dir=/tmp/rbi-client "$URL"
------------------------------------------------------------------
EOF
