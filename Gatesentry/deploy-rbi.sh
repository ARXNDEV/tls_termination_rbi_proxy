#!/usr/bin/env bash
# ============================================================================
# deploy-rbi.sh — one-shot, idempotent deploy + verify of the RBI mic/camera
# stack to the VM. Run from the MAC (needs passwordless ssh to the VM + VPN up).
#
#   ./deploy-rbi.sh
#
# It rsyncs the code, rebuilds the isolated-browser image, restarts camrelay
# (with the placeholder watchdog) and the proxy (with the full isolate-host
# list + camera env), stops stale containers so fresh ones pick up the new
# image, then verifies the whole path end-to-end. Safe to run repeatedly.
#
# Reboot-proofing (v4l2loopback auto-load, persistent cert, systemd units) needs
# root and is a SEPARATE one-time step — see setup-persistence.sh (run on the VM).
# ============================================================================
set -uo pipefail

VM="${RBI_VM:-arun-kumar@172.29.11.239}"
VM_IP="${RBI_VM_IP:-172.29.11.239}"
SRC="$(cd "$(dirname "$0")" && pwd)"
ISOLATE_HOSTS="${RBI_ISOLATE_HOSTS:-youtube.com,teams.microsoft.com,teams.live.com,meet.google.com,webcammictest.com}"
REMOTE="~/tls-termination-proxy/Gatesentry"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '   \033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '   \033[1;33m! %s\033[0m\n' "$*"; }

# ---- 0. reachability --------------------------------------------------------
say "0/6  VM reachable?"
if ! ssh -o BatchMode=yes -o ConnectTimeout=8 "$VM" 'echo ok' >/dev/null 2>&1; then
  warn "VM ($VM) unreachable — connect the VPN and re-run. Aborting (nothing changed)."
  exit 1
fi
ok "ssh to $VM works"

# ---- 1. rsync code ----------------------------------------------------------
say "1/6  rsync code -> VM"
rsync -az "$SRC/rbi/camrelay.py"        "$VM:$REMOTE/rbi/camrelay.py"
rsync -az --delete "$SRC/rbi/rbi-chrome/" "$VM:$REMOTE/rbi/rbi-chrome/"
ok "synced camrelay.py + rbi-chrome/ (inject-head.html, ext/, entrypoint.sh, …)"

# ---- 2. rebuild the isolated-browser image ---------------------------------
say "2/6  rebuild rbi-chrome-neko:latest"
ssh "$VM" "cd $REMOTE && docker build -t rbi-chrome-neko:latest rbi/rbi-chrome" \
  && ok "image rebuilt" || { warn "image build failed"; exit 1; }

# ---- 3. restart camrelay (placeholder watchdog) -----------------------------
say "3/6  restart camrelay"
ssh "$VM" "VMIP='$VM_IP' bash -s" <<'EOF'
pkill -f camrelay.py 2>/dev/null; sleep 1
if [ ! -f /tmp/camrelay-cert.pem ]; then
  echo "   ! /tmp/camrelay-cert.pem missing — minting a self-signed cert (run setup-persistence.sh for an Accops-CA-signed one trusted by the Mac)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=$VMIP" \
    -addext "subjectAltName=IP:$VMIP" \
    -keyout /tmp/camrelay-key.pem -out /tmp/camrelay-cert.pem >/dev/null 2>&1 || true
fi
cd ~/tls-termination-proxy/Gatesentry/rbi
nohup python3 camrelay.py > ~/camrelay.log 2>&1 &
sleep 3
pgrep -f camrelay.py >/dev/null && echo "   camrelay up (pid $(pgrep -f camrelay.py | head -1))" || { echo "   camrelay FAILED — tail ~/camrelay.log:"; tail -5 ~/camrelay.log; }
EOF

# ---- 4. restart proxy with persisted env + stop stale containers ------------
say "4/6  restart proxy (isolate-hosts persisted) + clear stale containers"
ssh "$VM" "ISOLATE='$ISOLATE_HOSTS' VMIP='$VM_IP' bash -s" <<'EOF'
pkill -f gatesentrybin 2>/dev/null; sleep 1
cd ~/tls-termination-proxy/Gatesentry
# persist the launch env so a manual/systemd restart keeps the same hosts
cat > ~/rbi-proxy.env <<ENV
RBI_ISOLATE_HOSTS=$ISOLATE
RBI_NAT1TO1=$VMIP
RBI_WEBCAM_DEVICE=/dev/video10
ENV
RBI_ISOLATE_HOSTS="$ISOLATE" RBI_NAT1TO1="$VMIP" RBI_WEBCAM_DEVICE=/dev/video10 \
  nohup ./bin/gatesentrybin config.json > /tmp/gatesentry-proxy.log 2>&1 &
sleep 2
pgrep -f gatesentrybin >/dev/null && echo "   proxy up (isolate=$ISOLATE)" || { echo "   proxy FAILED:"; tail -5 /tmp/gatesentry-proxy.log; }
n=$(docker ps -q --filter ancestor=rbi-chrome-neko:latest | wc -l | tr -d ' ')
docker ps -q --filter ancestor=rbi-chrome-neko:latest | xargs -r docker stop >/dev/null 2>&1
echo "   stopped $n stale container(s) — next visit spawns fresh ones from the new image"
EOF

# ---- 5. verify device feed + image inject ----------------------------------
say "5/6  verify camera plumbing"
ssh "$VM" 'bash -s' <<'EOF'
if pgrep -fa "ffmpeg.*video10" >/dev/null; then echo "   ✓ a writer is feeding /dev/video10 (device enumerable)"; else echo "   ! NO writer on /dev/video10 — check ~/camrelay.log"; fi
lsmod | grep -q v4l2loopback && echo "   ✓ v4l2loopback loaded" || echo "   ! v4l2loopback NOT loaded — run setup-persistence.sh (sudo)"
echo "   ext/inject.js deadlock-fix baked in image: $(docker run --rm --entrypoint grep rbi-chrome-neko:latest -c vInflight /opt/rbi/ext/inject.js 2>/dev/null) (want >=1)"
echo "   inject-head.html real-media override baked: $(docker run --rm --entrypoint grep rbi-chrome-neko:latest -c __rbiRealMedia /opt/rbi/inject-head.html 2>/dev/null) (want >=1)"
EOF

# ---- 6. verify isolation from the Mac --------------------------------------
say "6/6  verify isolation (Mac -> proxy)"
for h in youtube.com webcammictest.com meet.google.com; do
  code=$(curl -s -x "$VM_IP:8080" -k -H 'Sec-Fetch-Dest: document' "https://$h/" -o /dev/null -w '%{http_code}' --max-time 20 2>/dev/null)
  echo "   $h via proxy -> HTTP $code"
done

say "DONE."
echo "Open the demo window on https://webcammictest.com — camera should appear within ~2s."
echo "Mic: confirmed working. Camera: placeholder keeps the device enumerable so the"
echo "isolated getUserMedia succeeds, emits cam-on, and the Mac feed replaces the black frame."
