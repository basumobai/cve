#!/usr/bin/env bash
# Optional official apt repository setup for Trivy.
set -Eeuo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi
if [[ ! -r /etc/os-release ]]; then echo "Missing /etc/os-release" >&2; exit 1; fi
. /etc/os-release
if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
  echo "Only Ubuntu/Debian supported." >&2; exit 1
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y wget gnupg ca-certificates
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
wget -qO "$tmp" https://aquasecurity.github.io/trivy-repo/deb/public.key
test -s "$tmp"
gpg --batch --yes --dearmor -o /usr/share/keyrings/trivy.gpg "$tmp"
chmod 0644 /usr/share/keyrings/trivy.gpg
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main' \
  >/etc/apt/sources.list.d/trivy.list
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y trivy
trivy --version
echo "Trivy installed. Daily CVE Guard runs will refresh vulnerability databases as needed."
