# Gatesentry — TLS-Termination Proxy + Remote Browser Isolation (RBI)

**One line:** A consent-based, content-filtering web gateway that terminates TLS (SSL-bump), inspects/filters traffic, and — for risky or selected sites — transparently redirects the user into a throwaway, sandboxed cloud browser and streams back only pixels. The user's real device never touches the risky page.

---

## 1. The problem we're solving

Two classic enterprise/parental-control problems, solved together:

1. **You cannot filter what you cannot see.** Modern web traffic is HTTPS-encrypted end to end, so a normal proxy sees only opaque bytes. To enforce content policy (block categories, scan MIME types, filter words/images, time limits, YouTube restrictions), the gateway must *terminate* TLS, inspect the plaintext, then re-encrypt — a deliberate, consent-based "man in the middle" where **the client is configured to trust our CA**.

2. **Even allowed sites can be dangerous.** Some pages carry active threats (malware, drive-by exploits, phishing). Instead of blindly blocking or blindly allowing, we **isolate**: the page actually runs in a disposable container in our infrastructure, and the user only receives a live video/WebRTC stream of it. No page code ever executes on the user's machine.

This is **defensive technology** — the user (or their admin) installs and trusts the proxy on purpose. It is the same model used by enterprise secure web gateways (Zscaler, Cloudflare Gateway, Menlo Security, etc.).

---

## 2. How it works (end-to-end flow)

```
                          ┌─────────────────────────────────────────────────────┐
                          │                  GATESENTRY GATEWAY                   │
                          │                                                       │
  ┌────────┐   HTTPS      │  ┌───────────────┐      ┌────────────────────────┐   │
  │ Client │──────────────┼─▶│ TLS-Termination│      │   RBI Controller       │   │
  │browser │  trusts our  │  │  Proxy (MITM)  │      │ (per-session manager)  │   │
  │  (PAC) │   CA cert    │  │  - SNI peek    │      └───────────┬────────────┘   │
  └────────┘              │  │  - mint leaf   │                  │ docker run     │
       ▲                  │  │  - filters     │                  ▼                │
       │  pixels (WebRTC) │  └───────┬────────┘     ┌─────────────────────────┐   │
       │                  │          │ allow/block/  │  Throwaway RBI container │   │
       └──────────────────┼──────────┤ ISOLATE       │  - Chrome (kiosk)        │   │
                          │          ▼               │  - 1 session = 1 URL     │   │
                          │   normal filtered web    │  - nftables default-DROP │   │
                          │                          │  - streams via coturn    │   │
                          │                          └─────────────────────────┘   │
                          └─────────────────────────────────────────────────────┘
```

**Step by step:**

1. The client device is pointed at the proxy (via a PAC file we serve) and has our root CA installed in its trust store.
2. A request for `https://site.com` arrives. The proxy **peeks the TLS ClientHello** to read the SNI (the hostname) *without* completing the handshake.
3. The proxy **mints a leaf certificate** for that hostname on the fly (signed by our CA, with proper SAN + ServerAuth EKU so browsers accept it), caches it, and completes the handshake with the client. It now sees plaintext.
4. **Filters run** on the decrypted request/response: blocked hosts, blocked MIME types, word/image filters, time-of-day rules, YouTube restrictions, etc.
5. **Decision:**
   - **Allow** → proxy fetches the real site and relays it (re-encrypted to the client).
   - **Block** → a block page is returned.
   - **Isolate** → for a top-level navigation (detected via `Sec-Fetch-Dest: document`), the proxy rewrites the response into a **viewer page**. Behind the scenes the **RBI Controller launches a fresh container** running Chrome locked to that one URL, and the client gets a WebRTC stream of it.
6. When the user goes idle or disconnects, the container is **destroyed** (no state survives).

---

## 3. The two major subsystems

### A. TLS-Termination / SSL-Bump Proxy
The interception engine. Responsibilities:
- ClientHello/SNI parsing
- On-the-fly leaf certificate minting + caching (CA-signed, browser-valid)
- The full content-filter chain
- Deciding allow / block / isolate per request

Implemented in two places in this repo:
- **`Gatesentry/` (Go)** — the production proxy (`gatesentryproxy/`), the running service, filters, config, CA management. This is the primary, working implementation.
- **`tlsproxyQT/` (C++ / Qt 6 + OpenSSL 3)** — a parallel native implementation of the SSL-bump core (peek ClientHello → `startServerEncryption`, RAII OpenSSL wrappers, leaf-cert cache). A focused, modern rewrite of the bump logic.

### B. Remote Browser Isolation (RBI)
The "run it somewhere else and stream pixels" engine.
- **Controller** (`Gatesentry/gatesentryproxy/controller/session.go`, Go): manages **per-session, throwaway** browser containers. One container = one session = one allowed URL. Handles `Launch` / `Touch` / `Teardown`, idle garbage-collection, and the shared egress allowlist.
- **RBI container image** (`Gatesentry/rbi/rbi-chrome/`, built as `rbi-chrome-neko:latest`): neko v3 + **Chromium**, **URL-locked** via Chromium managed policy (`URLBlocklist:["*"]` + one-host allowlist), behind a default-DROP firewall, with the **gatesentry CA pre-trusted** in Chromium's NSS store (so the bumping proxy's certs are accepted). Streams the desktop to the client over WebRTC. (Chromium is used instead of Google Chrome because it renders under arm64 emulation *and* on x86; the google-chrome build SIGTRAPs under QEMU.)
- **coturn** TURN relay: the only media path out of the isolated network (relay-only ICE, no direct/host candidates).

**Streaming backend decision (locked): neko.** We standardize on **neko** (`ghcr.io/m1k1o/neko/google-chrome`) as the production streaming engine, not selkies. Rationale: RBI is "render a web page and stream pixels," not GPU cloud-gaming — neko is batteries-included (web viewer + signaling + WebRTC + multiuser), and its session model maps 1:1 onto our throwaway "one container = one URL" design, which keeps per-session launch/teardown simple and reliable. Selkies' edge (GPU NVENC, gaming-grade high-FPS latency, k8s density) only matters at hundreds-of-concurrent-sessions GPU scale — a clean future migration if we ever hit it, not a current need. The legacy selkies single-container demo (`glass-fence-rbi-chrome:local`) is deprecated; it existed only as an arm64-Mac render proof.

---

## 4. Security model (this is the important part)

The whole point is that the isolated browser is **boxed in on multiple independent layers**, so a compromised page cannot reach the internet, the proxy, or other sessions.

| Layer | Mechanism | What it guarantees |
|-------|-----------|--------------------|
| **Per-session isolation** | One throwaway container per session, no shared profile volume | A compromise dies with the session; users never share state |
| **Layer A — egress allowlist** | Controller only permits network egress to the *active session's own host* (exact + subdomain match) | The isolated browser can't reach arbitrary sites; no "re-isolation loop" |
| **Layer B — container firewall** | `nftables` **default-DROP** output chain inside the container; only DNS, the egress proxy port, and the TURN relay are allowed; drops are rate-limited + logged + counted | Even if the browser tries to bypass the proxy, raw egress is blocked at the kernel |
| **URL lockdown** | Chrome **managed policy**: `URLBlocklist:["*"]` + `URLAllowlist:[<the one host>]`, forced egress proxy, devtools/downloads/popups/sync **off** | The user can only ever load the one redirected URL — no other tabs, no escape |
| **Least privilege** | Docker **default** cap set + **only** `NET_ADMIN` (for nftables), `no-new-privileges`, not privileged | Minimal blast radius; not a root-equivalent container |
| **Fail-closed** | The container entrypoint exits *before* starting the browser if the firewall, supervisor, or policy can't be verified | A misconfigured box never comes up with open egress |
| **Idle GC + teardown** | Idle sessions are reaped automatically; disconnect destroys the container | No orphaned, internet-connected browsers linger |

**Secrets** (e.g. `TURN_SECRET`) come from the environment (`rbi.env`), never hardcoded. The CA private key is never logged. System-trust changes are performed by the operator, not by the software.

---

## 5. Current status (verified 2026-06-18)

The security and isolation logic is **built and verified**. Live video streaming is the only piece gated on hardware (see the caveat).

| # | Capability | Status |
|---|-----------|--------|
| 1 | Per-session containers, no shared profile | ✅ Verified |
| 2 | nftables default-DROP egress (direct egress + counter) | ✅ Verified |
| 3 | Proxy-bypassing fetch blocked (Layer B) | ✅ Verified |
| 4 | Page renders correctly in isolation (e.g. YouTube) | ✅ neko/Chromium renders here; **live stream needs x86-64** |
| 4b | Locked neko-chromium image (URL lock + CA trust + firewall) | ✅ Built & verified (`rbi-chrome-neko:latest`) |
| 5 | Egress allowlist / no re-isolation loop | ✅ Verified (controller unit tests) |
| 6 | Idle GC + teardown on disconnect | ✅ Verified (controller unit tests + live teardown) |

**The one caveat — hardware:** development happened on an **Apple-Silicon (arm64) Mac**, which runs the x86-64 browser image under QEMU emulation. Pages **render** correctly under neko (verified live: a neko/Chromium container rendered youtube.com at 1920×1080 on this Mac). The only emulation limit is that the **live WebRTC video encode/stream is slow** — not the rendering. On a **native x86-64 host** (our deployment target) this is a non-issue. A deploy guide for x86 is in `Gatesentry/DEPLOY-x86.md`.

> **Note on the browser binary:** neko's **google-chrome** build crashes under QEMU on arm64 (`is_brk_instruction` SIGTRAP), but neko's **chromium** build renders fine. For a Mac-renderable RBI image, base the per-session container on neko **chromium**; on native x86-64 either works.

---

## 6. Repo layout (key paths)

```
Gatesentry/                         # the Go gateway (primary, running service)
├── gatesentryproxy/
│   ├── proxy.go                    # interception + filter chain + isolate decision
│   └── controller/session.go       # per-session RBI container manager
│   └── controller/..._test.go      # security-logic unit tests (allowlist, GC)
├── application/filters/            # the content filters (hosts, MIME, words, time, YouTube)
├── rbi/
│   ├── rbi.env                     # single source of truth for all RBI config
│   ├── rbi-chrome/                 # the throwaway browser image (Dockerfile, entrypoint, policy)
│   ├── coturn/                     # TURN relay config
│   ├── docker-compose.yml          # gatesentry + coturn + isolated/edge networks
│   └── scripts/verify-rbi.sh       # live acceptance test (the 6 checks above)
├── config.json                     # gateway config incl. the CA (cert/key)
├── rbi-ca.cert.pem                 # the CA cert clients must trust
└── DEPLOY-x86.md                   # native x86-64 deployment guide

tlsproxyQT/                         # parallel C++/Qt6+OpenSSL3 SSL-bump implementation
```

---

## 7. How to run it

**Gateway (proxy) — works today, any platform:**
- Build & run the Go service in `Gatesentry/`. Proxy listens on `:8080`; the PAC server on `:8001`.
- Point the client at the PAC file and install `rbi-ca.cert.pem` into the client's trust store (operator action).

**Full per-session RBI stack — best on native x86-64:**
- Configure `Gatesentry/rbi/rbi.env` (public IP, TURN secret, ports).
- `docker compose up -d` in `Gatesentry/rbi/`.
- Run `scripts/verify-rbi.sh` to assert all six acceptance criteria.

---

## 8. What's left / next steps

- **Deploy on a native x86-64 host** to unlock reliable live media (the only emulation-limited piece).
- **Wire the per-session controller into the running proxy binary** end-to-end (the launch path is implemented and unit-tested; building the combined `gatesentry:rbi` image lets `verify-rbi.sh` run start-to-finish through the live proxy rather than via direct container launch + unit tests).
- Continue hardening / expanding the filter set as policy needs grow.

---

*This is legitimate, consent-based defensive security infrastructure: a content-filtering secure web gateway with browser isolation. The TLS interception works only because the client is deliberately configured to trust the gateway's CA — the standard model for enterprise and parental-control web security.*
