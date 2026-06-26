#!/usr/bin/env bash
# ============================================================================
# deploy-native-camera.sh — deploy the NATIVE WebRTC camera (peer-hook). Run from
# the MAC (needs ssh to the VM + VPN up).
#
#   ./deploy-native-camera.sh
#
# How it works (no client rebuild, no camrelay): the deployed RBI image is vanilla
# neko v3.1.4. Its server has webcam capture (capture.webcam -> v4l2sink /dev/video10)
# and its client shares the MIC natively, but the client ships NO camera-share. So the
# proxy injects two scripts (in proxy.go):
#   * rbiCapturePeer  — wraps window.RTCPeerConnection at <head> start to capture the
#                       client's peer into window.__rbiPeer (before neko's bundle runs).
#   * rbiNativeCamera — on first gesture (once peer-connected + host), adds a sendonly
#                       VP8 video track to that SAME peer. The client's own
#                       onnegotiationneeded sends the native offer; the server routes it
#                       OnTrack -> capture.Webcam -> v4l2sink /dev/video10. Same rails as
#                       the mic. The container's Chromium then reads /dev/video10.
#
# Deploys with `go build` + proxy restart only (no docker image rebuild -> sidesteps the
# corporate-VPN ghcr.io TLS-interception). camrelay is STOPPED: neko's v4l2sink must be
# the SOLE writer of /dev/video10. To revert to the camrelay JPEG fallback: ./deploy-rbi.sh
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

say "0/5  VM reachable?"
if ! ssh -o BatchMode=yes -o ConnectTimeout=8 "$VM" 'echo ok' >/dev/null 2>&1; then
  warn "VM ($VM) unreachable — connect the VPN and re-run. Aborting (nothing changed)."
  exit 1
fi
ok "ssh to $VM works"

say "1/5  rsync proxy source (rbiCapturePeer + rbiNativeCamera)"
rsync -az "$SRC/gatesentryproxy/proxy.go"       "$VM:$REMOTE/gatesentryproxy/proxy.go"
rsync -az "$SRC/gatesentryproxy/rbi_session.go" "$VM:$REMOTE/gatesentryproxy/rbi_session.go"
ok "synced proxy.go + rbi_session.go"

say "2/5  rebuild Go proxy on VM"
ssh "$VM" "cd $REMOTE && go build -o bin/gatesentrybin ." && ok "proxy rebuilt" || { warn "go build failed"; exit 1; }

say "3/5  stop camrelay (neko's v4l2sink is now the sole /dev/video10 writer)"
ssh "$VM" 'bash -s' <<'EOF'
pkill -f "[c]amrelay.py" 2>/dev/null
pkill -f "ffmpeg.*video10" 2>/dev/null
sleep 1
pgrep -f "[c]amrelay.py" >/dev/null && echo "   ! camrelay still up" || echo "   camrelay stopped"
EOF

say "4/5  restart proxy (NO RBI_CLIENT_DIST -> baked v3.1.4 client) + clear stale containers"
ssh "$VM" "ISO='$ISOLATE_HOSTS' VMIP='$VM_IP' bash -s" <<'EOF'
pkill -f gatesentrybin 2>/dev/null; sleep 1
cd ~/tls-termination-proxy/Gatesentry
cat > ~/rbi-proxy.env <<ENV
RBI_ISOLATE_HOSTS=$ISO
RBI_NAT1TO1=$VMIP
RBI_WEBCAM_DEVICE=/dev/video10
ENV
RBI_ISOLATE_HOSTS="$ISO" RBI_NAT1TO1="$VMIP" RBI_WEBCAM_DEVICE=/dev/video10 \
  nohup ./bin/gatesentrybin config.json > /tmp/gatesentry-proxy.log 2>&1 &
sleep 2
pgrep -f gatesentrybin >/dev/null && echo "   proxy up" || { echo "   proxy FAILED"; tail -6 /tmp/gatesentry-proxy.log; }
docker ps -q --filter name=rbi-sess | xargs -r docker stop >/dev/null 2>&1
echo "   cleared stale containers; remaining=$(docker ps -q --filter name=rbi-sess | wc -l | tr -d ' ')"
EOF

say "5/5  verify injection + device"
ssh "$VM" 'bash -s' <<'EOF'
H=$(curl -s -x 127.0.0.1:8080 -k -H "Sec-Fetch-Dest: document" "https://webcammictest.com/" --max-time 25)
echo "$H" | grep -q "__rbiPeer" && echo "   ✓ rbiCapturePeer injected" || echo "   ! rbiCapturePeer MISSING"
echo "$H" | grep -q "addTransceiver" && echo "   ✓ rbiNativeCamera injected" || echo "   ! rbiNativeCamera MISSING"
echo "$H" | grep -q "Glass Fence" && echo "   ! Glass Fence leak" || echo "   ✓ no Glass Fence (clean baked client)"
lsmod | grep -q v4l2loopback && echo "   ✓ v4l2loopback loaded" || echo "   ! v4l2loopback NOT loaded (sudo modprobe ...)"
timeout 6 ffmpeg -loglevel error -f lavfi -i testsrc=size=64x48:rate=5 -frames:v 2 -pix_fmt yuv420p -f v4l2 /dev/video10 >/dev/null 2>&1 && echo "   ✓ /dev/video10 writable (healthy)" || echo "   ! /dev/video10 wedged — sudo modprobe -r v4l2loopback && sudo modprobe v4l2loopback video_nr=10 card_label='RBI Camera' exclusive_caps=1"
EOF

say "DONE."
echo "Open https://meet.google.com (or webcammictest.com / Teams) in the demo window, click"
echo "into the video (become host). The mic warms (native) and the camera is added natively to"
echo "the SAME WebRTC peer -> server capture.Webcam -> /dev/video10 -> the call site sees it."
echo
echo "Verify the native webcam track on the VM while a session is live:"
echo "  C=\$(docker ps --filter name=rbi-sess --format '{{.Names}}'|head -1)"
echo "  docker logs \$C 2>&1 | grep -iE 'webcam|v4l2|pipeline'   # expect a WEBCAM pipeline created"
echo "  fuser /dev/video10                                       # expect neko/gstreamer holding it"
echo
echo "Revert to the camrelay JPEG fallback if needed:  ./deploy-rbi.sh"
