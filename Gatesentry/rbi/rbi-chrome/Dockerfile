# Per-session RBI browser: neko v3 + CHROMIUM (renders under arm64 QEMU emulation,
# unlike the google-chrome build which SIGTRAPs) + nftables (Layer B) + managed
# policy URL lockdown. neko's supervisor is preserved; our entrypoint only does
# fail-closed root setup, then execs it.
#
# Default base = the official neko chromium image (multi-arch: works on the arm64 Mac
# AND the x86-64 VM). Override with --build-arg NEKO_IMAGE=... to pin a digest/version
# or a custom base — same neko v3 layout, same policy.
ARG NEKO_IMAGE=ghcr.io/m1k1o/neko/chromium:latest
FROM ${NEKO_IMAGE}

USER root

# nftables (Layer B), envsubst (policy render), iproute2 (ss), curl (self-checks/verify),
# libnss3-tools (certutil — trust the proxy CA in Chromium's per-user NSS db).
# mesa-vulkan-drivers = lavapipe (software Vulkan) + libgl1-mesa-dri = llvmpipe (software GL):
# give Chromium a WORKING software-GPU backend in a GPU-less container so GPU-composited
# pages (desktop YouTube, Teams video grid, WebGL) RENDER instead of going black.
# Chromium's bundled SwiftShader fails to init here; lavapipe renders fine (verified).
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables gettext-base ca-certificates iproute2 curl libnss3-tools \
      mesa-vulkan-drivers libgl1-mesa-dri \
 && rm -rf /var/lib/apt/lists/*

# Chromium reads /etc/chromium/policies/managed; the google-chrome variant uses
# /etc/opt/chrome/... — create both so the entrypoint's auto-detect always finds one.
RUN mkdir -p /etc/chromium/policies/managed /etc/opt/chrome/policies/managed

# Trust the gatesentry TLS-bumping CA so the isolated browser accepts the proxy's
# minted leaf certs (otherwise every HTTPS site shows ERR_CERT_AUTHORITY_INVALID).
# System store here; the entrypoint also adds it to the neko user's NSS db (Chromium
# on Linux trusts NSS, not the system bundle, for cert validation).
COPY gatesentry-rbi-ca.crt /usr/local/share/ca-certificates/gatesentry-rbi-ca.crt
RUN update-ca-certificates

# Seamless mode: strip ALL client branding/chrome (Glass Fence header, threat
# sidebar, session log, footer, badges), force the neko video full-bleed, and put
# neko's real input element (<textarea class="overlay">) on TOP so mouse/cursor
# works. The CSS+JS payload lives in inject-head.html (a plain file — no shell/sed
# escaping) and is inserted inline before </head> via a perl slurp (the HTML is
# minified to one line, so a string replace is required, not a line-based tool).
COPY inject-head.html /opt/rbi/inject-head.html
RUN if [ -f /var/www/index.html ]; then \
      perl -0777 -i -pe 'BEGIN{open my $h,"<","/opt/rbi/inject-head.html" or die $!; local $/; our $inj=<$h>; close $h} s{</head>}{$inj</head>}' /var/www/index.html \
        || { echo "FATAL: head injection failed" >&2; exit 1; } ; \
      sed -i 's#<title>[^<]*</title>#<title></title>#' /var/www/index.html ; \
      grep -q 'textarea.overlay' /var/www/index.html || { echo "FATAL: inject verify failed (textarea.overlay missing)" >&2; exit 1; } ; \
    fi
# Make the connecting user the controller automatically: implicit hosting on,
# controls NOT locked, no admin-presence requirement, no inactive-cursor overlays.
# Together with admin auto-login the client gets FULL CONTROL on connect.
RUN if [ -f /etc/neko/neko.yaml ]; then \
      sed -i 's|implicit_hosting:.*|implicit_hosting: true|' /etc/neko/neko.yaml ; \
      grep -q 'inactive_cursors'   /etc/neko/neko.yaml || sed -i '/implicit_hosting:/a\  inactive_cursors: false' /etc/neko/neko.yaml ; \
      grep -q 'locked_controls'    /etc/neko/neko.yaml || sed -i '/implicit_hosting:/a\  locked_controls: false' /etc/neko/neko.yaml ; \
      grep -q 'control_protection' /etc/neko/neko.yaml || sed -i '/implicit_hosting:/a\  control_protection: false' /etc/neko/neko.yaml ; \
    fi

# Define the v3 video pipeline with show_pointer:false. neko v3 ignores the V2-style
# NEKO_CAPTURE_VIDEO_PIPELINE env (m1k1o/neko#610) and its built-in default bakes the
# cursor into the stream -> a second, laggy cursor. Appending capture.video.pipelines
# (show_pointer:false) captures the screen without the pointer, so only the viewer's
# own local cursor shows. Verified at build time so a bad merge fails the build.
COPY neko-capture.yaml /opt/rbi/neko-capture.yaml
# NOTE: guard on 'show_pointer: false' (NOT '^capture:') — neko v3.1.4's stock neko.yaml
# may already carry a capture: section, which made the old '^capture:' guard SKIP the merge
# so show_pointer:false was never added and the double cursor returned.
RUN if [ -f /etc/neko/neko.yaml ]; then \
      grep -q 'show_pointer: false' /etc/neko/neko.yaml || cat /opt/rbi/neko-capture.yaml >> /etc/neko/neko.yaml ; \
      grep -q 'show_pointer: false' /etc/neko/neko.yaml || { echo "FATAL: capture pipeline merge failed" >&2; exit 1; } ; \
    fi

# Force the kiosk browser FULLSCREEN reliably. neko's stock openbox rule only matched
# name="chromium*" role="browser" with <maximized>, so if chromium restarts mid-session
# (crash + window-bounds restore) and reopens a tiny ~200x200 window, the rule can miss
# it and the stream is mostly black. Broaden the match to ANY Chromium-class window and
# force <fullscreen> so whatever size/role chromium opens, the WM fills the screen.
RUN if [ -f /etc/neko/openbox.xml ]; then \
      perl -0777 -i -pe 's{<application class="Chromium\*"[^>]*>.*?</application>}{<application class="Chromium*">\n      <decor>no</decor>\n      <maximized>true</maximized>\n      <fullscreen>yes</fullscreen>\n      <focus>yes</focus>\n      <layer>normal</layer>\n    </application>}s' /etc/neko/openbox.xml \
        || { echo "FATAL: openbox rule patch failed" >&2; exit 1; } ; \
      grep -q '<application class="Chromium\*">' /etc/neko/openbox.xml || { echo "FATAL: openbox fullscreen patch verify failed" >&2; exit 1; } ; \
    fi

COPY chrome-policy.template.json    /opt/rbi/chrome-policy.template.json
COPY chromium-kiosk.template.conf   /opt/rbi/chromium-kiosk.template.conf
COPY entrypoint.sh                  /opt/rbi/entrypoint.sh
# RBI Media Bridge extension: detects the isolated app's camera/mic usage and signals
# the host so the user's real device is captured only on demand (loaded via
# --load-extension in the kiosk command).
COPY ext                            /opt/rbi/ext
RUN chmod 0755 /opt/rbi/entrypoint.sh

# Entrypoint does fail-closed setup then execs the neko supervisor using
# NEKO_SUPERVISORD_BIN/CONF (from rbi.env via the controller). No CMD: the
# version-specific exec is env-driven and single-sourced.
ENTRYPOINT ["/opt/rbi/entrypoint.sh"]
