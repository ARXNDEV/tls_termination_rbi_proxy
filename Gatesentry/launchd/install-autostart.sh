#!/usr/bin/env bash
# Installs gatesentry RBI auto-start as USER LaunchAgents (no sudo) so the proxy
# and the youtube-only PAC server come back automatically after every login/reboot.
# The system PAC setting itself already persists; this just keeps the two servers
# behind it alive. Remove anytime with uninstall-autostart.sh.
set -euo pipefail

LA="$HOME/Library/LaunchAgents"
HERE="$(cd "$(dirname "$0")" && pwd)"
PACDIR="$HOME/.gatesentry-rbi/pac"

mkdir -p "$LA" "$PACDIR"

# Keep the served PAC in a persistent, ISOLATED dir (never serve the Gatesentry
# dir — it holds config.json with the CA private key).
cp "$HERE/../youtube-only.pac" "$PACDIR/youtube-only.pac"
echo "PAC staged at $PACDIR/youtube-only.pac"

# Stop any manually-started instances so the agents can bind :8080 / :8009.
pkill -f gatesentrybin 2>/dev/null || true
pkill -f "http.server 8009" 2>/dev/null || true
sleep 1

# Install + (re)load both user agents.
for a in com.gatesentry.proxy com.gatesentry.pac; do
  cp "$HERE/$a.plist" "$LA/$a.plist"
  launchctl unload "$LA/$a.plist" 2>/dev/null || true
  launchctl load -w "$LA/$a.plist"
  echo "loaded $a"
done

# Optional: start Docker Desktop at login (RBI containers need the daemon up).
if osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Applications/Docker.app", hidden:true}' >/dev/null 2>&1; then
  echo "added Docker.app to login items"
else
  echo "NOTE: could not add Docker login item — enable Docker > Settings > General > 'Start Docker Desktop when you sign in' instead."
fi

sleep 2
echo "--- status ---"
launchctl list | grep gatesentry || true
echo "proxy :8080 -> $(curl -s -o /dev/null -w '%{http_code}' -x 127.0.0.1:8080 -k https://www.youtube.com/ 2>/dev/null || echo DOWN)"
echo "pac   :8009 -> $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8009/youtube-only.pac 2>/dev/null || echo DOWN)"
echo
echo "Done. After login the proxy + PAC auto-start; just open youtube.com in your normal Chrome."
