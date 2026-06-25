#!/usr/bin/env bash
# ============================================================================
# setup-persistence.sh — ONE-TIME reboot-proofing for the RBI mic/camera stack.
# Run ON THE VM, with sudo:   sudo bash setup-persistence.sh
#
# Makes everything survive a reboot:
#   1. v4l2loopback auto-loads on boot as /dev/video10 ("RBI Camera"), mode 0666
#   2. camrelay TLS cert is minted from the Accops CA (config.json) into a PERSISTENT
#      path (so the Mac trusts the cross-origin wss) — not /tmp (which clears on boot)
#   3. systemd services for the proxy and camrelay (auto-start on boot, auto-restart)
#
# Idempotent: safe to re-run. After this, the day-to-day deploy is just deploy-rbi.sh
# from the Mac (no sudo needed).
# ============================================================================
set -uo pipefail
[ "$(id -u)" = "0" ] || { echo "Run with sudo: sudo bash setup-persistence.sh"; exit 1; }

RUN_USER="${SUDO_USER:-arun-kumar}"
HOME_DIR="$(getent passwd "$RUN_USER" | cut -d: -f6)"
GS="$HOME_DIR/tls-termination-proxy/Gatesentry"
VM_IP="${RBI_VM_IP:-172.29.11.239}"
CERT_DIR="/etc/rbi"
say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# ---- 1. v4l2loopback: load now + on every boot, fixed node + perms ----------
say "1/4  v4l2loopback persistence (/dev/video10, mode 0666)"
echo 'v4l2loopback' > /etc/modules-load.d/rbi-v4l2loopback.conf
echo 'options v4l2loopback video_nr=10 card_label="RBI Camera" exclusive_caps=1' > /etc/modprobe.d/rbi-v4l2loopback.conf
# udev: keep the node world-writable so the user-space camrelay ffmpeg can write it
echo 'KERNEL=="video10", SUBSYSTEM=="video4linux", MODE="0666"' > /etc/udev/rules.d/99-rbi-v4l2.rules
udevadm control --reload 2>/dev/null || true
# FORCE a clean reload: after many ffmpeg start/kills the loopback gets stuck
# (ioctl(VIDIOC_G_FMT): Invalid argument) and ffmpeg can no longer write it. Stop any
# holders, remove the module, and reload it fresh so /dev/video10 is always healthy.
pkill -9 -f camrelay.py 2>/dev/null || true
pkill -9 -f 'ffmpeg.*video10' 2>/dev/null || true
sleep 1
modprobe -r v4l2loopback 2>/dev/null || true
modprobe v4l2loopback video_nr=10 card_label="RBI Camera" exclusive_caps=1 \
  || echo "   ! modprobe failed (install: apt-get install -y v4l2loopback-dkms)"
[ -e /dev/video10 ] && { chmod 0666 /dev/video10; echo "   /dev/video10 reloaded clean: $(ls -l /dev/video10)"; } || echo "   ! /dev/video10 not present"

# ---- 2. persistent camrelay cert, signed by the Accops CA in config.json -----
say "2/4  camrelay cert (Accops-CA signed) -> $CERT_DIR"
mkdir -p "$CERT_DIR"; chmod 755 "$CERT_DIR"
python3 - "$GS/config.json" "$CERT_DIR" "$VM_IP" <<'PY' || echo "   ! cert mint via config.json failed (will fall back to self-signed)"
import sys, json, base64, subprocess, os, re
cfg_path, out_dir, vmip = sys.argv[1], sys.argv[2], sys.argv[3]
ca_crt = os.path.join(out_dir, "accops-ca.crt"); ca_key = os.path.join(out_dir, "accops-ca.key")
leaf   = os.path.join(out_dir, "camrelay-cert.pem"); lkey = os.path.join(out_dir, "camrelay-key.pem")
data = json.load(open(cfg_path))
def find(keys):
    for k in keys:
        if k in data and isinstance(data[k], str) and len(data[k]) > 40: return data[k]
    return None
cd = find(["cert_data","CertData","certData","ca_cert","caCert"])
kd = find(["key_data","KeyData","keyData","ca_key","caKey"])
if not cd or not kd: raise SystemExit("cert_data/key_data not found in config.json")
def deco(s):
    try: return base64.b64decode(s)
    except Exception: return s.encode()
open(ca_crt,"wb").write(deco(cd)); open(ca_key,"wb").write(deco(kd))
# mint a leaf for the VM IP, signed by the Accops CA (so the Mac, which trusts the
# Accops CA, accepts the wss://VMIP:8443 camera-relay connection without warnings)
subprocess.run(["openssl","req","-newkey","rsa:2048","-nodes","-keyout",lkey,
    "-out","/tmp/camrelay.csr","-subj","/CN=%s"%vmip],check=True,
    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
ext="/tmp/camrelay.ext"; open(ext,"w").write("subjectAltName=IP:%s\n"%vmip)
subprocess.run(["openssl","x509","-req","-in","/tmp/camrelay.csr","-CA",ca_crt,"-CAkey",ca_key,
    "-CAcreateserial","-days","825","-extfile",ext,"-out","/tmp/camrelay-leaf.pem"],check=True,
    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
# fullchain = leaf + CA
open(leaf,"wb").write(open("/tmp/camrelay-leaf.pem","rb").read()+b"\n"+open(ca_crt,"rb").read())
print("   minted Accops-CA-signed cert -> %s (SAN IP:%s)"%(leaf,vmip))
PY
# self-signed fallback if the CA mint didn't produce files
if [ ! -f "$CERT_DIR/camrelay-cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$VM_IP" \
    -addext "subjectAltName=IP:$VM_IP" \
    -keyout "$CERT_DIR/camrelay-key.pem" -out "$CERT_DIR/camrelay-cert.pem" >/dev/null 2>&1
  echo "   ! used SELF-SIGNED cert — the Mac must trust it, or camera wss will fail. Prefer the Accops-CA path."
fi
chmod 644 "$CERT_DIR"/camrelay-cert.pem 2>/dev/null; chmod 640 "$CERT_DIR"/camrelay-key.pem 2>/dev/null
chgrp "$RUN_USER" "$CERT_DIR"/camrelay-key.pem 2>/dev/null || true

# ---- 3. systemd services (auto-start + auto-restart) ------------------------
say "3/4  systemd services (rbi-camrelay, rbi-proxy)"
cat > /etc/systemd/system/rbi-camrelay.service <<UNIT
[Unit]
Description=RBI camera relay (Mac camera -> /dev/video10)
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_USER
WorkingDirectory=$GS/rbi
Environment=RBI_WEBCAM_DEVICE=/dev/video10
Environment=RBI_CAM_CERT=$CERT_DIR/camrelay-cert.pem
Environment=RBI_CAM_KEY=$CERT_DIR/camrelay-key.pem
ExecStart=/usr/bin/python3 $GS/rbi/camrelay.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

# the proxy env file is written by deploy-rbi.sh; provide a sane default if absent
[ -f "$HOME_DIR/rbi-proxy.env" ] || cat > "$HOME_DIR/rbi-proxy.env" <<ENV
RBI_ISOLATE_HOSTS=youtube.com,teams.microsoft.com,teams.live.com,meet.google.com,webcammictest.com
RBI_NAT1TO1=$VM_IP
RBI_WEBCAM_DEVICE=/dev/video10
ENV
chown "$RUN_USER":"$RUN_USER" "$HOME_DIR/rbi-proxy.env"

cat > /etc/systemd/system/rbi-proxy.service <<UNIT
[Unit]
Description=GateSentry RBI TLS-termination proxy
After=network-online.target docker.service rbi-camrelay.service
Wants=network-online.target

[Service]
User=$RUN_USER
WorkingDirectory=$GS
EnvironmentFile=$HOME_DIR/rbi-proxy.env
ExecStart=$GS/bin/gatesentrybin config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable rbi-camrelay.service rbi-proxy.service >/dev/null 2>&1
echo "   enabled rbi-camrelay + rbi-proxy (start on boot)"

# ---- 4. (re)start them now --------------------------------------------------
say "4/4  start services"
# stop any manually-launched copies so systemd owns them
pkill -f camrelay.py 2>/dev/null || true
pkill -f gatesentrybin 2>/dev/null || true
sleep 1
systemctl restart rbi-camrelay.service
sleep 2
systemctl restart rbi-proxy.service
sleep 2
echo "   camrelay: $(systemctl is-active rbi-camrelay.service)   proxy: $(systemctl is-active rbi-proxy.service)"

say "DONE — reboot-proof. Day-to-day: just run deploy-rbi.sh from the Mac to push code."
echo "Verify: systemctl status rbi-camrelay rbi-proxy ; ls -l /dev/video10 ; pgrep -fa 'ffmpeg.*video10'"
