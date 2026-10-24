#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi
if [[ ! -r /etc/os-release ]]; then echo "Missing /etc/os-release" >&2; exit 1; fi
. /etc/os-release
if [[ "$ID" != "ubuntu" ]]; then
  echo "This opt-in script supports Ubuntu only." >&2; exit 1
fi
echo "Opt-in: install unattended-upgrades, enable APT daily update and Ubuntu unattended upgrades."
echo "Does not upgrade aaPanel PHP/Node/Docker images or restart containers."
echo "Review /etc/apt/apt.conf.d/50unattended-upgrades after installation."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT
cat >/etc/apt/apt.conf.d/90cve-guard-reboot-policy <<'APT'
Unattended-Upgrade::Automatic-Reboot "false";
APT
echo "APT unattended upgrades enabled. Review origins/pinning before relying on security-only policy:"
grep -n -E 'Allowed-Origins|Origins-Pattern|security|Automatic-Reboot' \
  /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/90cve-guard-reboot-policy || true
