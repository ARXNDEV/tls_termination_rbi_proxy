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
  grep -q -- "--app=$ALLOWED_URL" "$KIOSK_CONF" || fail "kiosk conf missing --app=$ALLOWED_URL"
  log "kiosk locked to $ALLOWED_URL (no tabs/omnibox):"; grep -m1 'command=/usr/bin/chromium' "$KIOSK_CONF" >&2
else
  log "WARN: kiosk template or supervisor dir missing — browser will not be kiosk-locked"
fi

# ---- hand off to neko (version-specific exec, single-sourced) ----------------
log "exec $NEKO_SUPERVISORD_BIN -c $NEKO_SUPERVISORD_CONF"
exec "$NEKO_SUPERVISORD_BIN" -c "$NEKO_SUPERVISORD_CONF"
