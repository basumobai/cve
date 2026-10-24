#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)." >&2; exit 1; fi
if ! command -v systemctl >/dev/null || ! command -v python3 >/dev/null; then
  echo "Requires systemd and python3." >&2; exit 1
fi
SOURCE="$(cd "$(dirname "$0")/.." && pwd)"
install -d -m 0755 /usr/local/lib/cve-guard
install -d -m 0700 /etc/cve-guard /var/lib/cve-guard/reports
install -m 0755 "$SOURCE/src/cve_guard.py" /usr/local/lib/cve-guard/cve_guard.py
if [[ ! -f /etc/cve-guard/config.json ]]; then
  install -m 0600 "$SOURCE/config.example.json" /etc/cve-guard/config.json
fi
cat >/etc/systemd/system/cve-guard.service <<'UNIT'
[Unit]
Description=CVE Guard local read-only security audit
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
User=root
UMask=0077
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 /usr/local/lib/cve-guard/cve_guard.py --config /etc/cve-guard/config.json --output-dir /var/lib/cve-guard/reports
TimeoutStartSec=3h
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=full
StandardOutput=journal
StandardError=journal
UNIT
cat >/etc/systemd/system/cve-guard.timer <<'UNIT'
[Unit]
Description=Run CVE Guard local audit daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
Unit=cve-guard.service

[Install]
WantedBy=timers.target
UNIT
chmod 0644 /etc/systemd/system/cve-guard.service /etc/systemd/system/cve-guard.timer
systemctl daemon-reload
systemctl enable --now cve-guard.timer
echo "Installed. Review /etc/cve-guard/config.json then run:"
echo "  sudo systemctl start cve-guard.service"
echo "  sudo journalctl -u cve-guard.service -n 100 --no-pager"
echo "NOTE: Trivy is an optional external dependency; install it from official packages."
