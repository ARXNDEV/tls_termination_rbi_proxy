#!/usr/bin/env bash
# Removes the gatesentry RBI auto-start agents. Does NOT touch the system PAC
# setting (turn that off with: networksetup -setautoproxystate "Wi-Fi" off).
set -euo pipefail
LA="$HOME/Library/LaunchAgents"
for a in com.gatesentry.proxy com.gatesentry.pac; do
  launchctl unload "$LA/$a.plist" 2>/dev/null || true
  rm -f "$LA/$a.plist"
  echo "removed $a"
done
echo "Auto-start removed. (Docker login item, if added, remove via System Settings > General > Login Items.)"
