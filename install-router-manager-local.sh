#!/usr/bin/env bash
set -euo pipefail
if (( EUID != 0 )); then echo "Run with sudo" >&2; exit 1; fi
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGET=/usr/local/lib/router-manager
OLD=/home/ydoleh/chatgpt-router
for file in app.py index.html router-manager.service; do
  [[ -f "$HERE/$file" ]] || { echo "Missing $HERE/$file" >&2; exit 1; }
done
if systemctl is-active --quiet router-manager.service; then systemctl stop router-manager.service; fi
install -d -m 0755 "$TARGET"
if [[ -f "$TARGET/app.py" ]]; then cp -a "$TARGET/app.py" "$TARGET/app.py.bak.$(date +%Y%m%d%H%M%S)"; fi
install -m 0644 "$HERE/app.py" "$TARGET/app.py"
install -m 0644 "$HERE/index.html" "$TARGET/index.html"
# Copy optional local web assets, if they were installed alongside the previous application.
if [[ -d "$OLD/static" && ! -e "$TARGET/static" ]]; then cp -a "$OLD/static" "$TARGET/static"; fi
if [[ -f "$OLD/linux.svg" && ! -e "$TARGET/linux.svg" ]]; then cp -a "$OLD/linux.svg" "$TARGET/linux.svg"; fi
install -m 0644 "$HERE/router-manager.service" /etc/systemd/system/router-manager.service
systemctl daemon-reload
systemctl enable router-manager.service
if ss -H -ltn '( sport = :80 )' | grep -q .; then
  echo "WARNING: TCP port 80 is already in use. Stop the other server before starting Router Manager." >&2
  exit 1
fi
systemctl start router-manager.service
systemctl --no-pager --full status router-manager.service
