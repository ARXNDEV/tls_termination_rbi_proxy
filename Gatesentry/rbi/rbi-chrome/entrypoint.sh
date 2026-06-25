#!/usr/bin/env bash
# Fail-closed root setup for one throwaway RBI session, then hand to neko.
#   self-check : neko supervisor binary + config must exist (else exit 1)
#   Layer B    : nftables default-DROP egress (TURN-relay media model)
#   policy     : render Chrome managed policy (URL allowlist + forced egress proxy)
# ANY failure exits non-zero BEFORE Chrome/neko start — never open egress.
set -euo pipefail
log()  { echo "[rbi-entrypoint] $*" >&2; }
fail() { log "FATAL: $*"; exit 1; }

# ---- inputs (all from rbi.env via the controller's `docker run -e`) ----------
: "${ALLOWED_URL:?ALLOWED_URL required}"
: "${PROXY_HOST:?}"; : "${PROXY_PORT:?}"      # PROXY_PORT == RBI_EGRESS_PORT (RBI-OFF listener)
: "${TURN_HOST:?}";  : "${TURN_PORT:=3478}"
: "${DNS_SERVER:=127.0.0.11}"                 # docker embedded resolver
# Version-specific supervisor (single-sourced in rbi.env):
: "${NEKO_SUPERVISORD_BIN:=/usr/bin/supervisord}"
: "${NEKO_SUPERVISORD_CONF:=/etc/neko/supervisord.conf}"

# DEV/DEMO ONLY. When =1: skip the Layer-B firewall AND the forced egress proxy
# so the kiosk browser uses DIRECT internet and renders without the :3129 egress
# listener wired. The URL allowlist lock + kiosk are KEPT. NEVER set this in prod.
: "${RBI_DEMO_DIRECT:=0}"

# Managed-policy dir: Chromium reads /etc/chromium/...; google-chrome reads
# /etc/opt/chrome/...  Auto-detect (override with CHROME_POLICY_DIR if needed).
if [ -z "${CHROME_POLICY_DIR:-}" ]; then
  if   [ -d /etc/chromium/policies/managed ];   then CHROME_POLICY_DIR=/etc/chromium/policies/managed
  elif [ -d /etc/opt/chrome/policies/managed ]; then CHROME_POLICY_DIR=/etc/opt/chrome/policies/managed
  else CHROME_POLICY_DIR=/etc/chromium/policies/managed
  fi
fi
mkdir -p "$CHROME_POLICY_DIR"
POLICY_FILE="$CHROME_POLICY_DIR/policy.json"

# The base neko image ships its OWN managed policy (e.g. policies.json: extension
# force-installs + a different URL allow/blocklist). Chrome MERGES every *.json in
# the managed dir, and that stale file intermittently BLOCKS the allowed site
# ("This page is blocked"). Remove any pre-existing managed policy files so ONLY our
# rendered policy.json governs the kiosk.
find "$CHROME_POLICY_DIR" -maxdepth 1 -type f -name '*.json' ! -name 'policy.json' -delete 2>/dev/null || true

ALLOWED_HOST="$(printf '%s' "$ALLOWED_URL" | sed -E 's#^[A-Za-z]+://##; s#/.*$##; s#:[0-9]+$##')"
[ -n "$ALLOWED_HOST" ] || fail "cannot derive host from ALLOWED_URL=$ALLOWED_URL"
log "host=$ALLOWED_HOST egress=$PROXY_HOST:$PROXY_PORT turn=$TURN_HOST:$TURN_PORT (relay model)"

# ---- #1 supervisor self-check (fail fast, no half-started browser) -----------
if [ ! -x "$NEKO_SUPERVISORD_BIN" ] && ! command -v "$NEKO_SUPERVISORD_BIN" >/dev/null 2>&1; then
  log "resolved NEKO_SUPERVISORD_BIN=$NEKO_SUPERVISORD_BIN ; PATH=$PATH"
  log "candidates: $(command -v supervisord s6-svscan 2>/dev/null || true) ; ls /etc/neko: $(ls -1 /etc/neko 2>&1 || true)"
  fail "neko supervisor binary not found — reconcile NEKO_SUPERVISORD_BIN in rbi.env with your image"
fi
[ -f "$NEKO_SUPERVISORD_CONF" ] || { log "ls /etc/neko: $(ls -1 /etc/neko 2>&1 || true)"; fail "supervisor config not found: $NEKO_SUPERVISORD_CONF"; }
log "supervisor OK: $NEKO_SUPERVISORD_BIN -c $NEKO_SUPERVISORD_CONF"

if [ "$RBI_DEMO_DIRECT" = "1" ]; then
  log "########################################################################"
  log "# RBI_DEMO_DIRECT=1 — Layer-B firewall + forced egress proxy DISABLED.  #"
  log "# Browser uses DIRECT internet. DEMO/DEV ONLY — never use in production. #"
  log "########################################################################"
  PROXY_IP=""; TURN_IP=""
else
  # ---- #2 nft present? (fail closed) -----------------------------------------
  command -v nft >/dev/null 2>&1 || fail "nft missing — refusing to start with open egress"

  # ---- resolve peers BEFORE the firewall blocks DNS --------------------------
  PROXY_IP="$(getent hosts "$PROXY_HOST" | awk '{print $1; exit}')" || true
  TURN_IP="$(getent hosts "$TURN_HOST"  | awk '{print $1; exit}')"  || true
  [ -n "${PROXY_IP:-}" ] || fail "cannot resolve PROXY_HOST=$PROXY_HOST"
  [ -n "${TURN_IP:-}"  ] || fail "cannot resolve TURN_HOST=$TURN_HOST"
  log "resolved proxy=$PROXY_IP turn=$TURN_IP"

  # ---- Layer B: default-DROP output. TURN-relay media model ------------------
  # Media reaches the client ONLY via the coturn relay, so the sole media/signal
  # egress is to $TURN_IP. (neko's NEKO_WEBRTC_EPR is its INTERNAL source range and
  # needs no output rule in relay mode.) If you ever switch to direct/srflx you'd
  # instead allow `udp sport <EPR-range> accept` and publish those ports.
  nft list table inet rbi >/dev/null 2>&1 && nft delete table inet rbi   # idempotent
  nft -f - <<EOF || fail "nftables rule insertion failed"
table inet rbi {
  chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oifname "lo" accept
    ip daddr ${DNS_SERVER} udp dport 53 accept
    ip daddr ${DNS_SERVER} tcp dport 53 accept
    ip daddr ${PROXY_IP} tcp dport ${PROXY_PORT} accept
    ip daddr ${TURN_IP} accept
    counter limit rate 10/minute log prefix "rbi-egress-drop " drop
  }
  chain input   { type filter hook input   priority 0; policy accept; }
  chain forward { type filter hook forward priority 0; policy drop;   }
}
EOF

  # ---- #2 assert the policy is actually drop (else exit) ---------------------
  # nft normalises `priority 0` -> `priority filter`; match the output hook line
  # from the table listing (robust across nft versions/output forms).
  if ! nft list table inet rbi 2>/dev/null | grep -E 'hook output' | grep -q 'policy drop'; then
    log "ruleset: $(nft list table inet rbi 2>&1 || true)"
    fail "output chain is not default-drop — refusing to start"
  fi
  log "Layer B active (output policy drop):"; nft list table inet rbi >&2 || true
fi

# ---- Chromium managed policy: URL lockdown + forced egress proxy ($PROXY_PORT) --
ALLOWED_HOST="$ALLOWED_HOST" PROXY_HOST="$PROXY_HOST" PROXY_PORT="$PROXY_PORT" \
  envsubst '${ALLOWED_HOST} ${PROXY_HOST} ${PROXY_PORT}' \
  < /opt/rbi/chrome-policy.template.json \
  > "$POLICY_FILE" \
  || fail "policy render failed"
[ -s "$POLICY_FILE" ] || fail "policy render produced empty file"
if [ "$RBI_DEMO_DIRECT" = "1" ]; then
  # Keep the URL allowlist lock; switch the proxy to direct (browser uses the net directly).
  sed -i 's/"ProxyMode": "fixed_servers"/"ProxyMode": "direct"/; /"ProxyServer":/d' "$POLICY_FILE"
  log "managed policy rendered at $POLICY_FILE (DEMO direct egress, URL lock kept):"; cat "$POLICY_FILE" >&2
else
  grep -q "\"${PROXY_HOST}:${PROXY_PORT}\"" "$POLICY_FILE" \
    || fail "policy ProxyServer is not ${PROXY_HOST}:${PROXY_PORT} (egress port mismatch)"
  log "managed policy rendered at $POLICY_FILE (proxy ${PROXY_HOST}:${PROXY_PORT}):"; cat "$POLICY_FILE" >&2
fi

# MULTI-DOMAIN sites: Teams (login.live.com, teams.microsoft.com, *.office.net) and
# YouTube (googlevideo.com video, i.ytimg.com thumbnails, consent.youtube.com,
# accounts.google.com, gstatic.com) span MANY domains. A single-host URLAllowlist +
# URLBlocklist:["*"] blocks those -> video/consent/login fail ("This page is blocked").
# So for these sites drop the URLBlocklist and allow ALL navigation. The kiosk WINDOW
# lock (no tabs/omnibox for the client) AND the container isolation still apply — only
# the per-URL allowlist is lifted. DEMO use only.
case "$ALLOWED_HOST" in
  teams.live.com|teams.microsoft.com|www.youtube.com|youtube.com|m.youtube.com|meet.google.com)
    sed -i 's/"URLBlocklist": \[[^]]*\]/"URLBlocklist": []/' "$POLICY_FILE"
    log "multi-domain site ($ALLOWED_HOST): URL lockdown relaxed (full site flow allowed)"
    ;;
esac

# ---- trust the proxy CA in the browser user's NSS db -------------------------
# Chromium on Linux validates TLS against its per-user NSS store, NOT the system
# CA bundle. Without this the bumping proxy's minted leaves -> ERR_CERT_AUTHORITY_INVALID.
CA_CRT=/usr/local/share/ca-certificates/gatesentry-rbi-ca.crt
BROWSER_USER="${BROWSER_USER:-neko}"
BROWSER_HOME="$(getent passwd "$BROWSER_USER" | cut -d: -f6)"; BROWSER_HOME="${BROWSER_HOME:-/home/$BROWSER_USER}"
if [ -f "$CA_CRT" ] && command -v certutil >/dev/null 2>&1; then
  NSSDB="$BROWSER_HOME/.pki/nssdb"
  mkdir -p "$NSSDB"
  certutil -d "sql:$NSSDB" -L >/dev/null 2>&1 || certutil -d "sql:$NSSDB" -N --empty-password >/dev/null 2>&1
  certutil -d "sql:$NSSDB" -A -t "C,," -n gatesentry-rbi -i "$CA_CRT" >/dev/null 2>&1 \
    && log "proxy CA trusted in $NSSDB" || log "WARN: certutil import failed (browser may show cert errors)"
  chown -R "$BROWSER_USER":"$BROWSER_USER" "$BROWSER_HOME/.pki" 2>/dev/null || true
else
  log "WARN: CA cert or certutil missing — isolated browser will not trust the proxy CA"
fi

# ---- kiosk-lock the browser to the one allowed URL --------------------------
# A COMPLETE Chromium runs here, but the client view is locked to ALLOWED_URL
# (no tabs/omnibox/new-tab). Render the supervisor program from the template.
KIOSK_TMPL=/opt/rbi/chromium-kiosk.template.conf
KIOSK_CONF=/etc/neko/supervisord/chromium.conf
if [ -f "$KIOSK_TMPL" ] && [ -d "$(dirname "$KIOSK_CONF")" ]; then
  ALLOWED_URL="$ALLOWED_URL" envsubst '${ALLOWED_URL}' < "$KIOSK_TMPL" > "$KIOSK_CONF" \
    || fail "kiosk conf render failed"
  grep -q -- "$ALLOWED_URL" "$KIOSK_CONF" || fail "kiosk conf missing $ALLOWED_URL"
  # Teams refuses to enable in-page audio/video on browsers it deems "unsupported"
  # (old/mobile UA -> "Unsupported Browser" wall, media disabled). Force a RECENT
  # EDGE desktop UA for teams sessions — Edge is Teams' first-class browser, so the
  # web meeting client loads with mic/camera enabled. (The template default is already
  # this same Edge UA; this keeps teams correct even if that default changes.)
  case "$ALLOWED_HOST" in
    teams.live.com|teams.microsoft.com)
      sed -i 's#--user-agent="[^"]*"#--user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0"#' "$KIOSK_CONF"
      log "teams session: recent Edge desktop user-agent forced (supported-browser + media)"
      ;;
  esac
  log "kiosk locked to $ALLOWED_URL (no tabs/omnibox):"; grep -m1 'command=/usr/bin/chromium' "$KIOSK_CONF" >&2
else
  log "WARN: kiosk template or supervisor dir missing — browser will not be kiosk-locked"
fi

# ---- template the camera-relay control URL into the in-container extension ---
# ext/content.js ships a __RBI_CONTROL_URL__ placeholder (with a hardcoded fallback).
# Point it at THIS deployment's relay so the camera works on any VM, not just the one
# baked into the fallback. The relay runs on the same host the client reaches for media
# (NEKO_WEBRTC_NAT1TO1). Best-effort; the in-file fallback covers the unset case.
CONTROL_HOST="${RBI_CONTROL_HOST:-${NEKO_WEBRTC_NAT1TO1:-}}"
if [ -f /opt/rbi/ext/content.js ] && [ -n "$CONTROL_HOST" ] && [ "$CONTROL_HOST" != "127.0.0.1" ]; then
  sed -i "s#__RBI_CONTROL_URL__#wss://${CONTROL_HOST}:8443/control?role=pub#" /opt/rbi/ext/content.js \
    && log "camera control URL templated -> wss://${CONTROL_HOST}:8443/control?role=pub" \
    || log "WARN: could not template control URL (extension keeps its built-in fallback)"
fi

# ---- make the client-mic virtual source the DEFAULT input -------------------
# neko pipes the client's microphone into the 'microphone' pulse virtual-source.
# Set it as the DEFAULT source so Teams/web apps auto-pick it as the mic. Pulse
# starts under the supervisor (after the exec below), so wait for it in a detached
# subshell (which survives exec) then set the default. Best-effort; never fatal.
(
  for _ in $(seq 1 40); do
    for sock in /tmp/pulseaudio.socket /run/user/*/pulse/native /var/run/pulse/native; do
      [ -S "$sock" ] && export PULSE_SERVER="unix:$sock"
    done
    if pactl info >/dev/null 2>&1; then
      # Prefer the REAL "microphone" virtual-source as the default input — NOT the
      # *.monitor sources. getUserMedia (Teams/Meet) works with either, but Chrome's
      # Web Speech engine (YouTube/Google voice search) does NOT capture from a monitor
      # source, so it must see a real source. Also boost the gain: the relayed client
      # mic arrives quiet, and speech recognition needs an audible level.
      if pactl list short sources 2>/dev/null | awk '{print $2}' | grep -qx microphone; then
        pactl set-default-source microphone >/dev/null 2>&1
        pactl set-source-volume microphone 300% >/dev/null 2>&1
        pactl set-source-volume audio_input.monitor 300% >/dev/null 2>&1
        echo "[rbi-entrypoint] default pulse source = microphone (real source, gain 300%)" >&2; break
      fi
      # fallback if the named source isn't present yet
      mic=$(pactl list short sources 2>/dev/null | awk '{print $2}' | grep -iE 'audio_input|microphone|mic' | head -1)
      [ -z "$mic" ] && mic=microphone
      pactl set-default-source "$mic" >/dev/null 2>&1 && { echo "[rbi-entrypoint] default pulse source = $mic" >&2; break; }
    fi
    sleep 1
  done
) >/dev/null 2>&1 &

# ---- hand off to neko (version-specific exec, single-sourced) ----------------
log "exec $NEKO_SUPERVISORD_BIN -c $NEKO_SUPERVISORD_CONF"
exec "$NEKO_SUPERVISORD_BIN" -c "$NEKO_SUPERVISORD_CONF"
