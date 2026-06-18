# Per-session RBI browser: neko v3 + CHROMIUM (renders under arm64 QEMU emulation,
# unlike the google-chrome build which SIGTRAPs) + nftables (Layer B) + managed
# policy URL lockdown. neko's supervisor is preserved; our entrypoint only does
# fail-closed root setup, then execs it.
#
# Default base = the chromium neko image verified to render on this arm64 Mac.
# Production on x86-64 may pin the official `ghcr.io/m1k1o/neko/chromium:3.0.4`
# (or a digest) via --build-arg NEKO_IMAGE=...  — same neko v3 layout, same policy.
ARG NEKO_IMAGE=arxndevv/glass-fence-chromium:latest
FROM ${NEKO_IMAGE}

USER root

# nftables (Layer B), envsubst (policy render), iproute2 (ss), curl (self-checks/verify),
# libnss3-tools (certutil — trust the proxy CA in Chromium's per-user NSS db).
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables gettext-base ca-certificates iproute2 curl libnss3-tools \
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

# Single-cursor: hide the client's LOCAL OS cursor over the neko video so only
# neko's rendered cursor shows (kills the double-cursor in the viewer).
RUN if [ -f /var/www/index.html ]; then \
      sed -i 's|height: 100%; }|height: 100%; } html,body,#glass-fence,#glass-fence *,.video-container,.video-container *,video,canvas{cursor:none !important;}|' /var/www/index.html ; \
    fi
# Make the connecting user the controller (implicit hosting) + drop inactive-cursor
# overlays — together with the CSS above this guarantees a SINGLE cursor.
RUN if [ -f /etc/neko/neko.yaml ]; then \
      sed -i 's|implicit_hosting:.*|implicit_hosting: true|' /etc/neko/neko.yaml ; \
      grep -q 'inactive_cursors' /etc/neko/neko.yaml || sed -i '/implicit_hosting:/a\  inactive_cursors: false' /etc/neko/neko.yaml ; \
    fi

COPY chrome-policy.template.json    /opt/rbi/chrome-policy.template.json
COPY chromium-kiosk.template.conf   /opt/rbi/chromium-kiosk.template.conf
COPY entrypoint.sh                  /opt/rbi/entrypoint.sh
RUN chmod 0755 /opt/rbi/entrypoint.sh

# Entrypoint does fail-closed setup then execs the neko supervisor using
# NEKO_SUPERVISORD_BIN/CONF (from rbi.env via the controller). No CMD: the
# version-specific exec is env-driven and single-sourced.
ENTRYPOINT ["/opt/rbi/entrypoint.sh"]
