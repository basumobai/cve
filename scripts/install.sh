#!/usr/bin/env bash
# Idempotent installer and upgrade path for Ubuntu 24.04.
set -Eeuo pipefail
[[ "$EUID" -eq 0 ]] || { echo '请使用 sudo bash scripts/install.sh' >&2; exit 2; }
mode="default"
if (( $# > 0 )); then
  [[ "$1" == "--no-trivy" ]] || { echo '仅支持可选参数 --no-trivy' >&2; exit 2; }
  mode="no-trivy"
fi
source_dir="$(cd "$(dirname "$0")/.." && pwd)"
for required in python3 systemctl install; do
  command -v "$required" >/dev/null || { echo "缺少依赖: $required" >&2; exit 2; }
done
for path in src/cve_guard.py src/site_discovery.py src/remediation.py src/risk.py scripts/cve config.example.json systemd/cve-guard.service systemd/cve-guard.timer; do
  [[ -f "$source_dir/$path" ]] || { echo "仓库文件不完整: $path" >&2; exit 2; }
done

if [[ "$mode" != "no-trivy" ]] && ! command -v trivy >/dev/null; then
  echo '安装 Trivy 漏洞扫描引擎（使用 Aqua 官方签名 APT 源）...'
  if ! bash "$source_dir/scripts/install-trivy.sh"; then
    echo '警告：Trivy 安装失败。巡检仍可工作，但漏洞扫描会报告未完成。' >&2
    echo '检查网络后运行: sudo bash scripts/install-trivy.sh' >&2
  fi
fi

install -d -m 0755 /usr/local/lib/cve-guard
install -d -m 0700 /etc/cve-guard /var/lib/cve-guard /var/lib/cve-guard/cache /var/lib/cve-guard/reports /var/lib/cve-guard/plans
install -m 0755 "$source_dir/src/cve_guard.py" /usr/local/lib/cve-guard/cve_guard.py
install -m 0644 "$source_dir/src/site_discovery.py" /usr/local/lib/cve-guard/site_discovery.py
install -m 0644 "$source_dir/src/remediation.py" /usr/local/lib/cve-guard/remediation.py
install -m 0644 "$source_dir/src/risk.py" /usr/local/lib/cve-guard/risk.py
install -m 0755 "$source_dir/scripts/cve" /usr/local/bin/cve

# Protect any previous user configuration during upgrades.
if [[ ! -e /etc/cve-guard/config.json ]]; then
  install -m 0600 "$source_dir/config.example.json" /etc/cve-guard/config.json
fi
install -m 0644 "$source_dir/systemd/cve-guard.service" /etc/systemd/system/cve-guard.service
install -m 0644 "$source_dir/systemd/cve-guard.timer" /etc/systemd/system/cve-guard.timer
systemctl daemon-reload
systemctl enable --now cve-guard.timer >/dev/null
echo
echo 'CVE Guard 安装/升级完成。每天自动扫描；默认 /www/wwwroot。'
echo '  sudo cve scan       # 立即扫描'
echo '  sudo cve status     # 查看状态'
echo '  sudo cve report     # 最近报告'
echo '  sudo cve plan       # 自动生成的修复建议'
echo '  sudo cve prepare    # 预览 APT 更新'
echo '  sudo cve apply      # 仅人工确认后执行 APT 更新'
echo '  sudo cve update     # 更新扫描器'
if ! command -v trivy >/dev/null; then
  echo '⚠️ 尚未安装 Trivy。无法完成完整 CVE 检测。'
fi
