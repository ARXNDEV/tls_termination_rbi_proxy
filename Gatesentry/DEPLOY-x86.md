# Deploy the RBI stack on a native x86-64 host (fast + audio)

On Apple Silicon this stack runs **amd64-emulated** → slow video + broken audio
(`wireplumber` aborts under QEMU). On a **native x86-64 Linux host** the same
files run with hardware-speed software encoding and working audio. This is the
supported way to run it.

Two pieces deploy together:
- **RBI browser stack** — `neko-master 2/` (docker-compose.yaml + rbi-chrome/Dockerfile)
- **TLS-termination proxy** — `Gatesentry/` (the `gatesentrybin` Go binary + config.json)

---

## 1. Provision the host
- Any x86-64 (Intel/AMD) Linux box or cloud VM (AWS/GCP/DigitalOcean/Hetzner…).
- Recommended: ≥4 vCPU, 8 GB RAM (browser + software encode).
- Install Docker + Docker Compose v2, and Go 1.21+ (to build the proxy), e.g. Ubuntu:
  ```bash
  curl -fsSL https://get.docker.com | sh
  sudo apt-get install -y golang-go
  ```
- Note the host's **public IP** (call it `<PUBLIC_IP>`).

## 2. Copy the files to the host
Copy both folders (scp/rsync/git):
```bash
rsync -av "neko-master 2/"  user@<PUBLIC_IP>:~/rbi-stack/
rsync -av  Gatesentry/      user@<PUBLIC_IP>:~/gatesentry/
```

## 3. Configure for native + remote access
On the host, in `~/rbi-stack/docker-compose.yaml` (firefox service env):
- It already reads `SERVER_PUBLIC_IP` for TURN — just export it (step 5).
- **Raise quality** now that encoding is native (no emulation):
  ```yaml
  - SELKIES_FRAMERATE=30
  - SELKIES_VIDEO_BITRATE=8000
  - SELKIES_ENABLE_RESIZE=true
  ```
- (Audio works natively — `wireplumber` won't crash on real hardware.)

## 4. Open the firewall (host + cloud security group)
| Port | Proto | For |
|---|---|---|
| 8081 | tcp | selkies viewer (the isolated browser stream) |
| 3478 | tcp+udp | embedded TURN (WebRTC signaling/relay control) |
| 49152–49171 | udp | TURN media relay range |
| 8080 | tcp | gatesentry TLS-termination proxy (if clients use the proxy) |
| 8001 | tcp | PAC file server (optional) |

## 5. Build + run
```bash
# RBI browser stack
cd ~/rbi-stack
export SERVER_PUBLIC_IP=<PUBLIC_IP>
docker build --platform linux/amd64 -t glass-fence-rbi-chrome:local ./rbi-chrome
docker compose up -d firefox          # native amd64 → no emulation, fast + audio

# TLS-termination proxy (drives the isolated Chrome via `docker exec`)
cd ~/gatesentry
go build -o bin/gatesentrybin .
./bin/gatesentrybin config.json        # :8080 proxy, :8001 PAC
```

## 6. Use it
- **Direct viewer:** `http://<PUBLIC_IP>:8081` — the isolated Chrome kiosk, now
  smooth with sound.
- **Through the proxy** (client browser):
  1. Trust the CA once on the client:
     `Gatesentry/rbi-ca.cert.pem` → add as a trusted root (macOS:
     `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain rbi-ca.cert.pem`).
  2. Point the client browser at `http://<PUBLIC_IP>:8080` and browse — each
     top-level navigation opens in the isolated kiosk Chrome and streams back.

## Notes
- Container name is pinned (`neko-master2-firefox-1`) so the proxy's
  `docker exec ... rbi-open <url>` works regardless of the host directory name.
- For HTTPS/public exposure put the viewer + proxy behind TLS (the selkies WS is
  same-origin; `SELKIES_ENABLE_HTTPS=true` or a reverse proxy) and re-enable
  `SELKIES_ENABLE_BASIC_AUTH` if you want auth in front of the viewer.
- For many concurrent users, run one firefox container per session (scale) and a
  TURN relay range per container.
