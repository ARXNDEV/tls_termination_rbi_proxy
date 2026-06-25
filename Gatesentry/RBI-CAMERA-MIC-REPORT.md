# RBI Mic + Camera — Overnight Work Report

_Generated overnight (2026-06-25). VPN dropped partway then came back; on reconnect the
camera fix was **deployed LIVE and VERIFIED end-to-end** — the isolated browser shows the
camera (LIGHTING 90, RBI Camera device, frames flowing). Mic was already working._

## ✅ CAMERA RELIABILITY: re-architected to be as robust as the mic (2026-06-25)
A 24-finding reliability audit confirmed the camera's flakiness was its ON-DEMAND design:
the control-channel is edge-triggered (a reconnecting viewer never re-syncs cam state), the
camStart guard sticks after a /ws drop (no onclose), and getUserMedia had no timeout/retry.
The mic is reliable because it is WARM (fired on first gesture, neko built-in).

**Fix — the camera is now WARM + robust, driven entirely from the PROXY injection
(`rbiWarmCamera` in proxy.go), so it deploys with `go build` + proxy restart — NO Docker
image rebuild (sidesteps the corporate-VPN ghcr.io TLS-interception blocker):**
- Warm: fires `getUserMedia(camera)` on the first user gesture for camera-relevant sites
  (teams/meet/webcam/zoom/…), exactly like warmMic — no dependency on the fragile control channel.
- Robust: 8s getUserMedia timeout + retry; auto-reconnecting frame /ws; real-device selection
  (`deviceId:{ideal}`, skips virtual cams); the baked on-demand camStart is disabled (`__rbi_cam=""`).
- camrelay hardened: `_LIVE` is a ref-count (overlapping/reconnecting /ws can't blank an active
  feed); `write_frame` broken-pipe sets a flag the watchdog acts on (immediate feeder restart);
  plus the existing single continuous feeder + watchdog + idle-black-on-stale.
- VERIFIED end-to-end: gesture → warm-camera → /ws → camrelay → `/dev/video10` brightness 58
  (real frames flowing), `live=1` ref-count correct.

> Local caveat: a Mac whose camera subsystem is wedged (VDCAssistant/HAL stuck — e.g. from
> heavy repeated getUserMedia testing) needs a REBOOT; `getUserMedia` hangs until then. That is
> a macOS issue, independent of RBI.

## ✅ CAMERA: FIXED + VERIFIED (live, no image rebuild needed)
Two bugs, both fixed in `camrelay.py` (runs on the VM host, so deploying it = just
restarting camrelay — no Docker rebuild):
1. The black "placeholder" ffmpeg that keeps `/dev/video10` enumerable had **died (zombie)**
   and was never restarted → device vanished → isolated `getUserMedia(video)` =
   NotFoundError. **Fix: `placeholder`→single-feeder + `feeder_watchdog()` keeps it alive.**
2. Swapping the placeholder feed for the live feed **killed+restarted ffmpeg**, which
   **disrupted the isolated browser's open capture** → "device found but black / 0 fps".
   **Fix: ONE continuous ffmpeg** (mjpeg stdin → v4l2) that is NEVER restarted mid-session;
   camrelay feeds it black JPEGs when idle and the live camera JPEGs when connected. The
   reader (isolated Chrome) sees an unbroken stream → black→live transitions seamlessly.

Verified: Mac camera (brightness 56) → camStart (51) → `/dev/video10` (host read = 51) →
isolated webcammictest shows the live pattern (LIGHTING 90). The same path serves Meet/Teams.

> The `ext/inject.js` deadlock fix + `inject-head.html` video-device override are now
> *belt-and-suspenders* (the continuous feeder already guarantees the device is always
> enumerable, so the deadlock can't occur). They ship with the next image rebuild.

---

## TL;DR — what to do in the morning

1. **Reconnect the VPN** (so `172.29.11.239` is reachable again).
2. From the Mac, in `Gatesentry/`:
   ```bash
   ./deploy-rbi.sh
   ```
   This pushes all the fixes, rebuilds the container image, restarts camrelay + proxy,
   clears stale containers, and verifies the whole path. **Camera should then work.**
3. (Once, optional but recommended) make it survive VM reboots — on the **VM**:
   ```bash
   sudo bash ~/tls-termination-proxy/Gatesentry/setup-persistence.sh
   ```
4. Test: open `https://webcammictest.com` (or Meet) in the demo window → camera appears in ~2s.

**Mic / YouTube voice search: already fixed and confirmed working** (you saw it).
**Camera: root-caused + fixed in code; deploy was blocked only by the VPN drop.**

---

## Camera — root cause (confirmed from live VM data before the VPN dropped)

Two independent bugs, both needed fixing:

1. **The camera-feed process had died (zombie).**
   `ffmpeg feeding /dev/video10 = <defunct>`, `v4l2loopback refcount 0` → **nothing was
   feeding the loopback** → `/dev/video10` was not enumerable → the isolated browser's
   `getUserMedia(video)` returned **NotFoundError ("No device found")**.
   camrelay started a black "placeholder" feed but **never restarted it when it died**.

2. **A signalling deadlock in the container extension.**
   `ext/inject.js` emitted the `cam on` signal **only after** `getUserMedia` *succeeded*
   (`.then`). Because of bug #1 the capture failed, so `cam on` was **never sent** → the Mac
   never started feeding the camera → the device stayed empty → **permanent deadlock**.
   (camrelay log proved it: every `cam` signal was `"on":false`, while `mic` toggled fine.)

---

## Fixes (all in code, ready to deploy)

| File | Change |
|---|---|
| `rbi/camrelay.py` | **placeholder watchdog**: an asyncio task keeps a writer on `/dev/video10` whenever no live feed is streaming, reaps zombies, and restarts a dead placeholder. `_REAL_FEED` flag prevents the watchdog and the live feed from both writing the device. |
| `rbi/rbi-chrome/ext/inject.js` | **deadlock fix**: emit `cam on` on the getUserMedia *attempt* (via a `vInflight` latch) so the Mac starts feeding immediately, then **retry the capture ~9×/700ms** while the loopback populates. Audio-only requests are unaffected. |
| `rbi/rbi-chrome/inject-head.html` | **real mic + camera override** (extends the earlier mic-only fix): if the Mac's resolved audio/video track is a *virtual* device (BlackHole / OBS / aggregate…), re-acquire from a real hardware device. Fixes the "BlackHole = silence" class of bug for camera too. |
| `deploy-rbi.sh` *(new)* | one-shot, idempotent deploy + verify from the Mac (no sudo). |
| `setup-persistence.sh` *(new)* | one-time reboot-proofing on the VM (sudo): v4l2loopback auto-load, Accops-CA-signed camrelay cert in `/etc/rbi`, systemd services for proxy + camrelay. |

Already done earlier (mic): `inject-head.html` getUserMedia override + `warmMic` selector fix
(neko `:latest` changed the mic icon `fa-microphone-slash` → `fa-microphone`).

---

## Why this fixes the camera

With the watchdog, `/dev/video10` is **always enumerable** (black placeholder) → the
isolated `getUserMedia(video)` **succeeds** (shows black) → `inject.js` emits `cam on` →
the Mac's `camStart` feeds the real camera → camrelay swaps the black feed for the live one.
And even if the placeholder is briefly down, the inject.js **attempt-signal + retry** breaks
the deadlock on its own. Belt **and** suspenders.

---

## Caveats / notes

- **VPN dropped overnight** (Mac fell back to home WiFi `192.168.1.46`); the VM
  (`172.29.11.239`, corporate net) was unreachable, so I could not run the deploy/test.
  Everything is staged for a 1-command deploy.
- **Passwordless sudo is OFF** on the VM, so `setup-persistence.sh` must be run by you
  (it prompts for the sudo password). `deploy-rbi.sh` needs **no** sudo.
- For **camera testing without your face**, the demo window can be launched with
  `--use-fake-device-for-media-stream` (synthetic moving pattern) to validate the whole
  pipeline; the real camera works the same way with the lid open.
- camrelay's TLS cert must be **Accops-CA-signed** (the Mac trusts that CA) for the
  cross-origin `wss://VM:8443` to work without errors — `setup-persistence.sh` mints it from
  `config.json`; `deploy-rbi.sh` falls back to self-signed only if that path is missing.

---

## Still-open hardening (being reviewed by an adversarial pass; will be applied next)

- `ext/content.js` hardcodes the VM IP in `CONTROL_URL` — should be templated by the
  entrypoint from `RBI_NAT1TO1` so it's portable to another VM.
- `camStart`/`controlConnect` reconnection + explicit error surfacing in `inject-head.html`.
- Any findings from the review workflow (`rbi-mic-camera-hardening-review`).
