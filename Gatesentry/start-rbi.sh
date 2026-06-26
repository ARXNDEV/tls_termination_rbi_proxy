#!/usr/bin/env bash
# One-command launcher for the RBI demo stack (proxy + camera relay).
# Survives SSH disconnect (setsid) and re-applies the full working env every time.
# Usage on the VM:  ./start-rbi.sh
set -u
GS=/home/arun-kumar/tls-termination-proxy/Gatesentry
cd "$GS"

# --- camera relay: JPEG-over-wss -> ffmpeg -> /dev/video10 -----------------
# Needs a TLS cert at /tmp/camrelay-{cert,key}.pem. /tmp is wiped on reboot, so
# if the cert is gone the relay won't start — re-sign it (see notes) and re-run.
if ! pgrep -f camrelay.py >/dev/null 2>&1; then
  if [ -f /tmp/camrelay-cert.pem ] && [ -f /tmp/camrelay-key.pem ]; then
    ( cd rbi && RBI_WEBCAM_DEVICE=/dev/video10 RBI_CAM_PORT=8443 \
        setsid python3 camrelay.py >/tmp/camrelay.log 2>&1 </dev/null & )
    echo "camrelay started"
  else
    echo "WARNING: /tmp/camrelay-{cert,key}.pem missing -> camera relay NOT started (re-sign cert)"
  fi
else
  echo "camrelay already running"
fi

# --- proxy -----------------------------------------------------------------
pkill -f gatesentrybin 2>/dev/null; sleep 1
export RBI_ISOLATE_HOSTS=youtube.com,teams.microsoft.com,teams.live.com,meet.google.com,webcammictest.com
export RBI_NAT1TO1=172.29.11.239
export RBI_VIDEO_FPS=30
export RBI_VIDEO_RESOLUTION=1280x720
export RBI_WEBCAM_DEVICE=/dev/video10
export RBI_WEBRTC_ALLOW_UDP=1          # UDP media (this network doesn't throttle it)
export RBI_CLOSE_GRACE_MS=0            # instant per-tab teardown
export RBI_DEVICE_SCALE=0.75           # isolated-browser zoom
# setsid + </dev/null fully detaches so it survives the SSH session closing.
setsid ./bin/gatesentrybin config.json >/tmp/gatesentry-proxy.log 2>&1 </dev/null &
sleep 2
if pgrep -f gatesentrybin >/dev/null 2>&1; then
  echo "proxy up on :8080"
else
  echo "proxy FAILED -- check /tmp/gatesentry-proxy.log"; tail -5 /tmp/gatesentry-proxy.log
fi
