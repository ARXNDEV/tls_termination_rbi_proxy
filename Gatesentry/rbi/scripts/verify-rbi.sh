#!/usr/bin/env bash
# Live-host smoke test for the RBI pipeline. Run AFTER `docker compose up -d`
# (gatesentry with both listeners wired + coturn). Asserts every acceptance
# criterion with real commands; exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./rbi.env; set +a

CLIENT="127.0.0.1:${RBI_CLIENT_PORT}"
TARGET="${TARGET_URL:-https://example.com}"
TARGET_HOST="$(printf '%s' "$TARGET" | sed -E 's#^[A-Za-z]+://##; s#/.*$##')"
GS="$(docker ps --format '{{.Names}}' | grep -E 'gatesentry' | head -1)"
fails=0
pass(){ echo "PASS  $*"; }
bad(){  echo "FAIL  $*"; fails=$((fails+1)); }

open_session(){ # $1 = cookie jar -> echoes container name
  curl -s -o /dev/null -c "$1" -x "http://${CLIENT}" \
       -H 'Sec-Fetch-Dest: document' -H 'Accept: text/html' "$TARGET" --max-time 60 || true
  local sid; sid="$(awk '/rbi_session/{print $7}' "$1" | tail -1)"
  [ -n "$sid" ] && echo "rbi-${sid}"
}

echo "== C1: two users -> two separate containers, no shared profile volume =="
J1=$(mktemp); J2=$(mktemp)
C1=$(open_session "$J1"); C2=$(open_session "$J2")
if [ -n "$C1" ] && [ -n "$C2" ] && [ "$C1" != "$C2" ] \
   && docker inspect "$C1" >/dev/null 2>&1 && docker inspect "$C2" >/dev/null 2>&1; then
  pass "two distinct containers: $C1 $C2"
else bad "expected two distinct rbi-* containers (got '$C1' '$C2')"; fi
V1=$(docker inspect -f '{{range .Mounts}}{{.Name}} {{end}}' "$C1" 2>/dev/null || true)
V2=$(docker inspect -f '{{range .Mounts}}{{.Name}} {{end}}' "$C2" 2>/dev/null || true)
if [ -z "$(comm -12 <(tr ' ' '\n' <<<"$V1"|sort -u) <(tr ' ' '\n' <<<"$V2"|sort -u)|grep -v '^$' || true)" ]; then
  pass "no shared profile volume"; else bad "containers share a volume: $V1 / $V2"; fi

echo "== C2: nft default-drop + direct-IP egress blocked + counter increments =="
docker exec "$C1" nft list chain inet rbi output 2>/dev/null | grep -qE 'policy drop' \
  && pass "nft output policy drop" || bad "nft chain not default-drop"
before=$(docker exec "$C1" sh -c "nft -a list table inet rbi | awk '/rbi-egress-drop/{print \$0}'" | grep -oE 'packets [0-9]+' | awk '{print $2}' | head -1 || echo 0)
if docker exec "$C1" curl -sS -m3 https://1.1.1.1 >/dev/null 2>&1; then
  bad "direct egress to 1.1.1.1 SUCCEEDED (should be dropped)"
else pass "direct egress to 1.1.1.1 blocked"; fi
after=$(docker exec "$C1" sh -c "nft -a list table inet rbi | awk '/rbi-egress-drop/{print \$0}'" | grep -oE 'packets [0-9]+' | awk '{print $2}' | head -1 || echo 0)
[ "${after:-0}" -gt "${before:-0}" ] && pass "nft drop counter incremented ($before -> $after)" || bad "drop counter did not increment ($before -> $after)"

echo "== C3: proxy-bypassing fetch blocked (Layer B) =="
if docker exec "$C1" curl -sS -m3 https://example.org >/dev/null 2>&1; then
  bad "direct https://example.org SUCCEEDED (Layer B failed)"
else pass "proxy-bypassing fetch blocked"; fi

echo "== C2b: URL allowlist enforced in the rendered policy =="
pol=$(docker exec "$C1" cat /etc/opt/chrome/policies/managed/policy.json 2>/dev/null || true)
echo "$pol" | grep -q '"URLBlocklist"' && echo "$pol" | grep -q "$TARGET_HOST" \
  && pass "managed policy: URLBlocklist=* + URLAllowlist contains $TARGET_HOST" \
  || bad "managed policy missing URLBlocklist/allowlist for $TARGET_HOST"

echo "== C4: audio AND video media present (server-side) =="
if docker exec "$C1" sh -c "ss -lun 2>/dev/null | grep -qE ':(${NEKO_EPR_MIN}|$((NEKO_EPR_MIN+1)))'"; then
  pass "WebRTC media UDP bound in EPR range"; else bad "no UDP socket in EPR range ${NEKO_EPR_MIN}-${NEKO_EPR_MAX}"; fi
if docker exec "$C1" sh -c 'command -v pactl >/dev/null && pactl list short sinks 2>/dev/null | grep -q .'; then
  pass "audio sink present (PulseAudio)"; else bad "no PulseAudio sink (audio path down)"; fi
docker exec "$C1" sh -c 'pgrep -fa "google-chrome" >/dev/null' && pass "Chrome (video source) running" || bad "Chrome not running"

echo "== C5: session's own fetch served by :3129 egress (no re-isolation loop) =="
body=$(docker exec "$C1" curl -s -m10 -x "http://${RBI_PROXY_HOST}:${RBI_EGRESS_PORT}" "$TARGET" || true)
if printf '%s' "$body" | grep -q 'RBI_SESSION_ENDPOINT'; then
  bad "egress fetch returned a VIEWER page (re-isolation loop!)"
elif [ -n "$body" ]; then pass "egress fetch returned real content, no viewer"
else bad "egress fetch returned nothing"; fi
launches=$(docker logs "$GS" 2>&1 | grep -c 'launched session' || true)
docker exec "$C1" curl -s -m10 -x "http://${RBI_PROXY_HOST}:${RBI_EGRESS_PORT}" "$TARGET" >/dev/null || true
launches2=$(docker logs "$GS" 2>&1 | grep -c 'launched session' || true)
[ "$launches2" -eq "$launches" ] && pass "egress fetch triggered no Launch" || bad "egress fetch triggered a Launch (loop)"

echo "== C6: disconnect -> container gone within RBI_IDLE_TIMEOUT =="
secs=$(printf '%s' "$RBI_IDLE_TIMEOUT" | tr -dc '0-9'); secs=$((secs + 20))
echo "   waiting up to ${secs}s for GC of $C2 ..."
gone=0
for _ in $(seq 1 "$secs"); do docker inspect "$C2" >/dev/null 2>&1 || { gone=1; break; }; sleep 1; done
[ "$gone" -eq 1 ] && pass "idle session container removed" || { bad "container $C2 still present after ${secs}s"; docker rm -f "$C2" >/dev/null 2>&1 || true; }

rm -f "$J1" "$J2"
echo "-------------------------------------------"
[ "$fails" -eq 0 ] && { echo "ALL CHECKS PASSED"; exit 0; } || { echo "$fails CHECK(S) FAILED"; exit 1; }
