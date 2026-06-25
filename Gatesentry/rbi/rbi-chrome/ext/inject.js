// Runs in the PAGE (main world). Knows exactly when the isolated site uses the mic or
// camera — via getUserMedia (Meet/Teams/webcam) AND the Web Speech API
// (YouTube/Google voice search, which does NOT call getUserMedia). A single poll
// computes the combined state (so the two paths never fight) and posts changes to the
// content script. Handles software mute (track.enabled) and a debounce so quick repeat
// voice searches don't drop the mic.
(function () {
  if (window.__rbiMediaHooked) return;
  window.__rbiMediaHooked = 1;

  function emit(kind, on) {
    try { window.postMessage({ __rbi_media: 1, kind: kind, on: !!on }, "*"); } catch (e) {}
  }

  var vtracks = new Set(), atracks = new Set();
  var srActive = false, srOffTimer = null, micOffTimer = null;
  var lastV = null, lastA = null;
  var vInflight = 0;   // count of video getUserMedia calls currently attempting/retrying

  function poll() {
    // Cam is ON if a real video track is live OR a video getUserMedia is in flight. The
    // in-flight latch is CRITICAL: on the very first camera request the loopback device
    // may not be enumerable yet, so getUserMedia would fail and (without this) never emit
    // "cam on" -> the host never starts feeding -> permanent deadlock. By signalling ON on
    // the ATTEMPT, the host begins feeding /dev/video10 and our retry then succeeds.
    var vOn = vInflight > 0;
    vtracks.forEach(function (t) { if (t.readyState === "live") { if (t.enabled) vOn = true; } else vtracks.delete(t); });
    var aOn = srActive;   // mic is "on" if voice-search is listening OR an audio track is live
    atracks.forEach(function (t) { if (t.readyState === "live") { if (t.enabled) aOn = true; } else atracks.delete(t); });
    if (vOn !== lastV) { lastV = vOn; emit("cam", vOn); }
    // Mic with an OFF-debounce: turn ON instantly, but turn OFF only after 3s of no
    // use. Voice-search engines rapidly start/stop recognition; without this the mic
    // signal would flap on/off and the host mic would toggle, breaking the audio.
    if (aOn) {
      if (micOffTimer) { clearTimeout(micOffTimer); micOffTimer = null; }
      if (lastA !== true) { lastA = true; emit("mic", true); }
    } else if (lastA === true && !micOffTimer) {
      // keep the mic WARM for 30s after the last use, so the spin-up (~1s) doesn't make
      // a quick voice-search miss the first words and "Try again" works instantly.
      micOffTimer = setTimeout(function () { micOffTimer = null; lastA = false; emit("mic", false); }, 30000);
    }
  }
  setInterval(poll, 250);

  // getUserMedia — Meet / Teams / webcam-test / etc.
  var md = navigator.mediaDevices;
  if (md && md.getUserMedia) {
    var orig = md.getUserMedia.bind(md);
    md.getUserMedia = function (c) {
      var wantsVideo = !!(c && c.video);
      if (wantsVideo) { vInflight++; poll(); }   // signal "cam on" on the ATTEMPT (see poll)
      function settle() { if (wantsVideo) { vInflight = Math.max(0, vInflight - 1); poll(); } }
      // Retry video capture while the host feed populates the loopback. The device is
      // un-enumerable until ffmpeg writes the first frames (~1-2s after "cam on"), so the
      // first getUserMedia can NotFound/NotReadable; retry for ~6s before giving up.
      function attempt(left) {
        return orig(c).then(function (stream) {
          stream.getVideoTracks().forEach(function (t) { vtracks.add(t); });
          stream.getAudioTracks().forEach(function (t) { atracks.add(t); });
          settle(); poll();
          return stream;
        }, function (err) {
          var name = (err && err.name) || "";
          if (wantsVideo && left > 0 && /NotFound|NotReadable|OverconstrainedError|AbortError|TypeError/i.test(name)) {
            return new Promise(function (r) { setTimeout(r, 700); }).then(function () { return attempt(left - 1); });
          }
          settle();
          throw err;
        });
      }
      return attempt(wantsVideo ? 9 : 0);
    };
  }

  // Web Speech API — YouTube / Google voice search (no getUserMedia). Keep the mic on
  // for 4s after recognition ends so a quick repeat search doesn't miss the spin-up.
  [window.SpeechRecognition, window.webkitSpeechRecognition].forEach(function (SR) {
    if (!SR || !SR.prototype || SR.prototype.__rbiSR) return;
    SR.prototype.__rbiSR = 1;
    var start = SR.prototype.start;
    SR.prototype.start = function () {
      srActive = true;
      if (srOffTimer) { clearTimeout(srOffTimer); srOffTimer = null; }
      poll();
      var off = function () {
        if (srOffTimer) clearTimeout(srOffTimer);
        srOffTimer = setTimeout(function () { srActive = false; srOffTimer = null; poll(); }, 4000);
      };
      try { this.addEventListener("end", off); this.addEventListener("error", off); this.addEventListener("audioend", off); } catch (e) {}
      return start.apply(this, arguments);
    };
  });
})();
