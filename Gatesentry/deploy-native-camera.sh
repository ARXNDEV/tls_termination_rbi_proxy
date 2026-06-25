#!/usr/bin/env bash
# ============================================================================
# deploy-native-camera.sh — deploy the NATIVE WebRTC camera path (no Docker
# rebuild). Run from the MAC (needs ssh to the VM + VPN up).
#
#   ./deploy-native-camera.sh
#
# Background: the glass-fence fork's SERVER already has the native client->container
# webcam pipeline (webrtc OnTrack -> capture.Webcam() -> gstreamer v4l2sink
# /dev/video10), already compiled into the prod image and already enabled+mounted by
# rbi_session.go. The ONLY missing piece was the CLIENT enableCamera(); it now exists
# in the glass-fence client (client/src/glassfence/base.ts + a camera button in
# controls.vue). Because the client is just static files served from /var/www, we
# deploy the new client by BIND-MOUNTING its dist over /var/www — NO `docker build`
# (which the corporate VPN breaks via ghcr.io TLS-interception).
#
# This puts the camera on the SAME native WebRTC rails as the (reliable) mic and makes
# camrelay.py unnecessary. camrelay is STOPPED here because neko's v4l2sink and
# camrelay's ffmpeg must never both write /dev/video10 (two writers conflict).
# deploy-rbi.sh (the JPEG camrelay fallback) remains available if you need to revert.
# ============================================================================
set -uo pipefail

VM="${RBI_VM:-arun-kumar@172.29.11.239}"
VM_IP="${RBI_VM_IP:-172.29.11.239}"
SRC="$(cd "$(dirname "$0")" && pwd)"
ISOLATE_HOSTS="${RBI_ISOLATE_HOSTS:-youtube.com,teams.microsoft.com,teams.live.com,meet.google.com,webcammictest.com}"
REMOTE="~/tls-termination-proxy/Gatesentry"
# The glass-fence client source (sibling of tls-termination-proxy under ~/Downloads).
CLIENT_DIR="${RBI_CLIENT_DIR:-$SRC/../../neko-master 2/client}"
REMOTE_DIST="rbi-client-dist"   # under the VM home dir; resolved to absolute below

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

# ---- 1. build the client (native enableCamera) ------------------------------
say "1/6  build glass-fence client (npm run build)"
if [ ! -d "$CLIENT_DIR" ]; then
  warn "client dir not found: $CLIENT_DIR — set RBI_CLIENT_DIR. Aborting."
  exit 1
fi
( cd "$CLIENT_DIR" && NODE_OPTIONS=--openssl-legacy-provider npx vue-cli-service build ) \
  && ok "client built -> $CLIENT_DIR/dist" || { warn "client build failed"; exit 1; }
grep -rq "addTransceiver" "$CLIENT_DIR/dist/js/"*.js && ok "enableCamera present in dist" \
  || { warn "enableCamera NOT in dist — build is stale. Aborting."; exit 1; }

# ---- 2. rsync the client dist + proxy source -> VM --------------------------
say "2/6  rsync client dist + proxy source -> VM"
ssh "$VM" "mkdir -p ~/$REMOTE_DIST"
rsync -az --delete "$CLIENT_DIR/dist/" "$VM:~/$REMOTE_DIST/"
ok "synced dist -> ~/$REMOTE_DIST"
# the proxy source carries the RBI_CLIENT_DIST bind-mount in rbi_session.go
rsync -az "$SRC/gatesentryproxy/rbi_session.go" "$VM:$REMOTE/gatesentryproxy/rbi_session.go"
ok "synced rbi_session.go (RBI_CLIENT_DIST bind-mount)"

# ---- 3. rebuild the Go proxy on the VM (no Docker) --------------------------
say "3/6  rebuild Go proxy on VM"
ssh "$VM" "cd $REMOTE && go build -o bin/gatesentrybin . " \
  && ok "proxy rebuilt" || { warn "go build failed"; exit 1; }

# ---- 4. STOP camrelay (two-writers gotcha) ----------------------------------
say "4/6  stop camrelay (neko's v4l2sink is now the sole /dev/video10 writer)"
ssh "$VM" 'pkill -f "[c]amrelay.py" 2>/dev/null; pkill -f "ffmpeg.*video10" 2>/dev/null; sleep 1; \
  pgrep -f "[c]amrelay.py" >/dev/null && echo "   ! camrelay still up" || echo "   camrelay stopped"'

# ---- 5. restart proxy with RBI_CLIENT_DIST + clear stale containers ---------
say "5/6  restart proxy (RBI_CLIENT_DIST bind-mount) + clear stale containers"
ssh "$VM" "ISOLATE='$ISOLATE_HOSTS' VMIP='$VM_IP' DIST='$REMOTE_DIST' bash -s" <<'EOF'
pkill -f gatesentrybin 2>/dev/null; sleep 1
cd ~/tls-termination-proxy/Gatesentry
DISTABS="$HOME/$DIST"
cat > ~/rbi-proxy.env <<ENV
RBI_ISOLATE_HOSTS=$ISOLATE
RBI_NAT1TO1=$VMIP
RBI_WEBCAM_DEVICE=/dev/video10
RBI_CLIENT_DIST=$DISTABS
ENV
RBI_ISOLATE_HOSTS="$ISOLATE" RBI_NAT1TO1="$VMIP" RBI_WEBCAM_DEVICE=/dev/video10 \
  RBI_CLIENT_DIST="$DISTABS" \
  nohup ./bin/gatesentrybin config.json > /tmp/gatesentry-proxy.log 2>&1 &
sleep 2
pgrep -f gatesentrybin >/dev/null && echo "   proxy up (client dist=$DISTABS)" || { echo "   proxy FAILED:"; tail -5 /tmp/gatesentry-proxy.log; }
n=$(docker ps -q --filter name=rbi-sess | wc -l | tr -d ' ')
docker ps -q --filter name=rbi-sess | xargs -r docker stop >/dev/null 2>&1
echo "   stopped $n stale container(s) — next visit spawns fresh ones with the new client + native webcam"
EOF

# ---- 6. verify ---------------------------------------------------------------
say "6/6  verify"
ssh "$VM" 'bash -s' <<'EOF'
lsmod | grep -q v4l2loopback && echo "   ✓ v4l2loopback loaded (/dev/video10 ready for neko's v4l2sink)" || echo "   ! v4l2loopback NOT loaded — run setup-persistence.sh (sudo)"
[ -f "$HOME/rbi-client-dist/index.html" ] && echo "   ✓ client dist present on VM" || echo "   ! client dist missing on VM"
grep -rq addTransceiver "$HOME/rbi-client-dist/js/"*.js 2>/dev/null && echo "   ✓ enableCamera present in VM dist" || echo "   ! enableCamera NOT in VM dist"
EOF

say "DONE."
echo "Open https://teams.microsoft.com (or meet.google.com / webcammictest.com) in the demo"
echo "window. When you're in control of the isolated view, click the CAMERA button in the neko"
echo "controls (next to the mic). getUserMedia grabs your Mac camera and sends it natively over"
echo "WebRTC into the container's /dev/video10 — the call site sees it as a real camera."
echo
echo "Verify the native track on the VM (while a session is live):"
echo "  docker logs <rbi-sess-...>  2>&1 | grep -i 'webcam\\|OnTrack\\|video'"
echo "  docker exec <rbi-sess-...>  sh -c 'ls -l /dev/video10'"
echo
echo "If you must revert to the JPEG camrelay fallback:  ./deploy-rbi.sh"
