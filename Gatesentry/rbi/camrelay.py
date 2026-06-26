#!/usr/bin/env python3
# Accops HySecure — Camera Bridge.
#
# Streams the user's REAL (Mac) camera into the host v4l2loopback device
# (/dev/video10) so the isolated browser sees it as "RBI Camera". neko v3's client
# has no webcam send-path, so we feed the loopback ourselves:
#
#   Mac browser  --getUserMedia--> canvas JPEG frames --WebSocket-->  this relay
#   this relay   --mjpeg stdin-->  ONE long-lived ffmpeg  --v4l2-->  /dev/video10
#
# PRODUCTION DESIGN (single continuous feeder):
#   A SINGLE ffmpeg always reads an mjpeg stream from its stdin and writes
#   /dev/video10. camrelay feeds that stdin with BLACK frames when idle and with the
#   live camera frames when a Mac client is connected. The ffmpeg/producer is NEVER
#   killed/restarted while a session is live, so the isolated browser's capture is
#   never disrupted — fixes the "device found but black / 0 fps" writer-switch race
#   that happens when a placeholder feed is swapped for the live feed.
#
# Run on the VM host (or via the rbi-camrelay systemd service):
#   python3 camrelay.py        # listens on https://0.0.0.0:8443
#   env: RBI_WEBCAM_DEVICE (/dev/video10), RBI_CAM_PORT (8443),
#        RBI_CAM_CERT, RBI_CAM_KEY

import asyncio, ssl, subprocess, os, threading, time
from aiohttp import web

VIDEO_DEV = os.environ.get("RBI_WEBCAM_DEVICE", "/dev/video10")
PORT      = int(os.environ.get("RBI_CAM_PORT", "8443"))
CERT      = os.environ.get("RBI_CAM_CERT", "/tmp/camrelay-cert.pem")
KEY       = os.environ.get("RBI_CAM_KEY",  "/tmp/camrelay-key.pem")
W, H, FPS = 640, 480, 30

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Accops HySecure — Camera Bridge</title></head>
<body style="font-family:system-ui,sans-serif;background:#111;color:#eee;text-align:center;padding:36px">
<h2 style="color:#F26522;margin:0 0 6px">Accops HySecure — Camera Bridge</h2>
<p id="st">Starting…</p>
<video id="v" autoplay muted playsinline style="width:480px;max-width:90vw;border:2px solid #F26522;border-radius:10px;background:#000;transform:scaleX(-1)"></video>
<div style="margin-top:14px">
  <button id="btn" style="background:#F26522;color:#fff;border:0;border-radius:8px;padding:10px 22px;font-size:15px;cursor:pointer">⏸ Stop Camera</button>
</div>
<p style="opacity:.6;font-size:13px;margin-top:12px">Camera runs only while this is <b>Started</b>.<br>Your camera is the <b>RBI Camera</b> in isolated call sites (Teams/Meet).</p>
<script>
var st=document.getElementById('st'), v=document.getElementById('v'), btn=document.getElementById('btn');
var ws=null, stream=null, timer=null, keepCtx=null;
// Keep this tab UN-throttled when it is backgrounded. Chromium/Brave freeze setInterval
// + WebSocket in hidden/occluded tabs -> the capture loop stops -> camrelay flaps to
// idle-black (the demo shows LIGHTING 10 / black even though the camera is fine). A
// silent oscillator marks the tab as "playing audio", which exempts it from throttling.
function keepAlive(){ try{ if(!keepCtx){ keepCtx=new (window.AudioContext||window.webkitAudioContext)(); var o=keepCtx.createOscillator(); var g=keepCtx.createGain(); g.gain.value=0.0001; o.connect(g); g.connect(keepCtx.destination); o.start(); } if(keepCtx.state==='suspended'){ keepCtx.resume(); } }catch(e){} }
// connect() opens the /ws and AUTO-RECONNECTS on any drop (camrelay restart, network
// blip, throttle recovery) — so the bridge never needs a manual reload. The capture
// timer runs continuously and independently; it only sends while the WS is open.
function connect(){
  if(!stream) return;
  var proto=location.protocol==='https:'?'wss':'ws';
  try{ ws=new WebSocket(proto+'://'+location.host+'/ws'); }catch(e){ setTimeout(connect,1500); return; }
  ws.binaryType='arraybuffer';
  ws.onopen=function(){ st.innerHTML='<span style="color:#5f5">● LIVE</span> — camera streaming'; };
  ws.onclose=function(){ ws=null; if(stream){ st.innerHTML='<span style="color:#fa0">● reconnecting…</span>'; setTimeout(connect,1500); } };
  ws.onerror=function(){ try{ws.close();}catch(_){} };
}
async function start(){
  try{
    keepAlive();
    stream=await navigator.mediaDevices.getUserMedia({video:{width:640,height:480,frameRate:{ideal:15}},audio:false});
    v.srcObject=stream;
    var canvas=document.createElement('canvas'); canvas.width=640; canvas.height=480; var cx=canvas.getContext('2d');
    if(timer){ clearInterval(timer); }
    timer=setInterval(function(){
      if(!ws||ws.readyState!==1||!v.videoWidth) return;
      try{ cx.drawImage(v,0,0,640,480);
        canvas.toBlob(function(b){ if(b&&ws&&ws.readyState===1){ b.arrayBuffer().then(function(a){try{ws.send(a);}catch(_){}}); } },'image/jpeg',0.6);
      }catch(_){}
    }, 66);
    connect();
    btn.textContent='⏸ Stop Camera';
  }catch(e){ st.textContent='Camera error: '+(e&&e.message||e); }
}
function stop(){
  if(timer){ clearInterval(timer); timer=null; }
  if(stream){ stream.getTracks().forEach(function(t){t.stop();}); stream=null; }  // null FIRST so onclose won't reconnect
  if(ws){ try{ws.close();}catch(_){} ws=null; }
  v.srcObject=null;
  st.textContent='⏸ Camera stopped — click Start when you need it';
  btn.textContent='▶ Start Camera';
}
btn.onclick=function(){ keepAlive(); if(timer||stream) stop(); else start(); };
// resume the keepalive audio on ANY user gesture (AudioContext can start suspended)
['click','keydown','pointerdown','touchstart'].forEach(function(ev){document.addEventListener(ev,keepAlive,{passive:true});});
start();
</script></body></html>"""

# ---- single continuous feeder -----------------------------------------------
_FEED  = {"proc": None, "broken": False}  # the one long-lived ffmpeg (mjpeg stdin -> v4l2)
_LIVE  = {"n": 0}             # COUNT of live camera /ws connections (ref-count, not a bool:
                              # overlapping/reconnecting sockets must not let a stale finally
                              # flip an active feed back to idle -> black)
_LASTLIVE = {"t": 0.0}         # monotonic time of the last live frame received
_WLOCK = threading.Lock()      # serialize writes to ffmpeg.stdin (idle vs live)
BLACK_JPEG = b""               # one pre-encoded black 640x480 JPEG (set in main)

def _make_black_jpeg():
    try:
        p = subprocess.run(
            ["ffmpeg", "-loglevel", "error", "-f", "lavfi",
             "-i", "color=c=0x0a0a0a:s=%dx%d" % (W, H), "-frames:v", "1", "-f", "mjpeg", "pipe:1"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        return p.stdout or b""
    except Exception:
        return b""

def start_feeder():
    # ONE ffmpeg, never killed mid-session. Kill only strays before (re)start.
    try: subprocess.run(["pkill", "-f", "ffmpeg.*" + os.path.basename(VIDEO_DEV)], timeout=3)
    except Exception: pass
    p = subprocess.Popen(
        ["ffmpeg", "-loglevel", "warning", "-fflags", "nobuffer", "-flags", "low_delay",
         "-f", "mjpeg", "-use_wallclock_as_timestamps", "1", "-i", "pipe:0",
         # scale to a FIXED W×H + yuv420p so any producer resolution / a mid-stream size
         # change can't desync the v4l2 output format (VIDIOC_G_FMT EINVAL / header fail).
         "-vf", "scale=%d:%d,format=yuv420p" % (W, H),
         "-r", str(FPS), "-pix_fmt", "yuv420p", "-f", "v4l2", VIDEO_DEV],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
        stderr=open("/tmp/camrelay-ff.log", "ab", buffering=0))
    _FEED["proc"] = p
    _FEED["broken"] = False
    print("[camrelay] feeder ffmpeg started -> %s (pid %s)" % (VIDEO_DEV, p.pid), flush=True)
    return p

def feed_alive():
    # Also treat a BROKEN stdin (BrokenPipe seen on write) as dead so the watchdog restarts
    # immediately instead of waiting up to its interval while ffmpeg is a half-dead zombie.
    p = _FEED["proc"]
    return p is not None and p.poll() is None and p.stdin is not None and not _FEED["broken"]

def write_frame(data):
    p = _FEED["proc"]
    if not (p and p.stdin):
        return False
    with _WLOCK:
        try:
            p.stdin.write(data); p.stdin.flush(); return True
        except Exception:
            _FEED["broken"] = True   # actionable: feeder_watchdog restarts on this
            return False

async def idle_black_writer():
    # Push a black JPEG ~10 fps WHENEVER no live camera is connected, so the ffmpeg
    # producer never starves and the loopback stays enumerable with a steady stream.
    loop = asyncio.get_event_loop()
    while True:
        await asyncio.sleep(0.1)
        # Feed black when idle OR when a live client is connected but has gone SILENT
        # (camera spin-up, a hung getUserMedia, a frozen tab) — never let the loopback
        # starve, or the isolated browser's capture stalls to "0 fps".
        live = _LIVE["n"] > 0
        # Only treat a LIVE client as stale after a LONG silence (5s). At 9-15fps with
        # jitter/background-throttle, brief gaps (<5s) are normal — ffmpeg duplicates the
        # last REAL frame to hold the output rate, so the face stays on screen. The old
        # 0.5s threshold injected black on every tiny gap -> the camera flickered
        # face<->black ~1/sec ("kabhi photo aata hai, 1 sec baad jaata hai").
        stale = live and (time.monotonic() - _LASTLIVE["t"] > 5.0)
        if (not live or stale) and feed_alive() and BLACK_JPEG:
            await loop.run_in_executor(None, write_frame, BLACK_JPEG)

async def feeder_watchdog():
    while True:
        await asyncio.sleep(3)
        if not feed_alive():
            print("[camrelay] feeder dead -> restarting", flush=True)
            try: start_feeder()
            except Exception as e: print("[camrelay] feeder restart failed:", repr(e), flush=True)

async def index(request):
    return web.Response(text=PAGE, content_type="text/html")

# Control channel: in-container extension (role=pub) reports camera/mic on/off; the host
# viewer (role=sub) listens and turns the REAL device on/off on demand. Plain broadcast.
SUBS = set()
async def control_handler(request):
    role = request.query.get("role", "sub")
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    if role == "sub":
        SUBS.add(ws)
        print("[camrelay] control subscriber connected (%d)" % len(SUBS), flush=True)
        try:
            async for _m in ws: pass
        finally:
            SUBS.discard(ws)
    else:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                print("[camrelay] media signal:", msg.data, flush=True)
                for s in list(SUBS):
                    try: await s.send_str(msg.data)
                    except Exception: SUBS.discard(s)
    return ws

async def ws_handler(request):
    # Live camera frames from the Mac. We DON'T spawn/kill ffmpeg here — we just flip the
    # _LIVE flag (the idle black-writer pauses) and forward frames into the SAME feeder.
    ws = web.WebSocketResponse(max_msg_size=0)
    await ws.prepare(request)
    _LIVE["n"] += 1
    print("[camrelay] live camera connected -> forwarding to feeder (live=%d)" % _LIVE["n"], flush=True)
    loop = asyncio.get_event_loop()
    _dbg = {"n": 0}
    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.BINARY:
                _LASTLIVE["t"] = time.monotonic()
                if os.environ.get("RBI_CAM_DEBUG") and _dbg["n"] < 3:
                    try:
                        open("/tmp/camrelay-livesample-%d.jpg" % _dbg["n"], "wb").write(msg.data)
                        print("[camrelay] DEBUG saved live frame %d: %d bytes" % (_dbg["n"], len(msg.data)), flush=True)
                    except Exception: pass
                    _dbg["n"] += 1
                await loop.run_in_executor(None, write_frame, msg.data)
    finally:
        _LIVE["n"] = max(0, _LIVE["n"] - 1)
        print("[camrelay] live camera gone -> idle black (live=%d)" % _LIVE["n"], flush=True)
    return ws

async def _on_startup(app):
    global BLACK_JPEG
    BLACK_JPEG = _make_black_jpeg()
    print("[camrelay] black frame: %d bytes" % len(BLACK_JPEG), flush=True)
    start_feeder()
    app["idle"] = asyncio.ensure_future(idle_black_writer())
    app["wd"]   = asyncio.ensure_future(feeder_watchdog())

async def _on_cleanup(app):
    for k in ("idle", "wd"):
        try: app[k].cancel()
        except Exception: pass

def main():
    app = web.Application(client_max_size=0)
    app.add_routes([web.get("/", index), web.get("/ws", ws_handler), web.get("/control", control_handler)])
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    print("[camrelay] https://0.0.0.0:%d/  -> %s (single-feeder)" % (PORT, VIDEO_DEV), flush=True)
    web.run_app(app, host="0.0.0.0", port=PORT, ssl_context=ctx, print=None)

if __name__ == "__main__":
    main()
