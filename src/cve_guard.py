#!/usr/bin/env python3
"""CVE Guard: read-only local host and application security inventory.

Only reads system metadata, Docker configuration, and invokes security scanners.
Never executes exploit payloads or uploads host reports.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile

SENSITIVE_PORTS = {
    2375: "Docker API (unencrypted)",
    2376: "Docker API",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    6380: "Redis TLS/alternate",
    9200: "Elasticsearch",
    27017: "MongoDB",
    11211: "Memcached",
    8888: "Possible admin panel",
    7800: "Possible admin panel",
}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def run(argv, timeout=25, cwd=None):
    """Run a fixed argv list; no shell, bounded output, timeouts and failures recorded."""
    try:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                              errors="replace", timeout=timeout, check=False)
        return {"ok": proc.returncode == 0, "returncode": proc.returncode,
                "stdout": proc.stdout[:150000], "error": proc.stderr[:1200]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "returncode": None, "stdout": "",
                "error": f"{type(exc).__name__}: {exc}"}


def finding(kind, severity, title, evidence, remediation):
    return {"kind": kind, "severity": severity, "title": title,
            "evidence": evidence, "remediation": remediation}


def load_config(path):
    default = {"applications": [], "scan_docker_images": True,
               "scan_host_rootfs": False, "timeout_seconds": 360}
    if path:
        with open(path, "r", encoding="utf-8") as f:
            value = json.load(f)
        if not isinstance(value, dict):
            raise ValueError("config must be an object")
        default.update(value)
    if not isinstance(default["applications"], list):
        raise ValueError("applications must be an array")
    for app in default["applications"]:
        if not isinstance(app, dict) or not isinstance(app.get("path"), str):
            raise ValueError("each application needs a path")
    return default


def get_os():
    data = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k] = v.strip().strip('"')
    except OSError:
        pass
    return {"distribution": data.get("PRETTY_NAME", "unknown"),
            "kernel": os.uname().release,
            "hostname": socket.gethostname()}


def command_version(argv):
    result = run(argv)
    output = (result["stdout"] or result["error"]).strip()
    return output.splitlines()[0][:240] if output else "unavailable"


def inventory():
    versions = {}
    cmds = {
        "nginx": ["nginx", "-v"], "openresty": ["openresty", "-v"],
        "docker": ["docker", "--version"],
        "containerd": ["containerd", "--version"],
        "runc": ["runc", "--version"],
        "redis": ["redis-server", "--version"],
        "postgresql_client": ["psql", "--version"],
        "node": ["node", "--version"],
        "npm": ["npm", "--version"], "composer": ["composer", "--version"],
        "openssl": ["openssl", "version"], "ssh": ["ssh", "-V"],
    }
    for name, argv in cmds.items():
        if shutil.which(argv[0]):
            versions[name] = command_version(argv)
    php_bins = sorted(Path("/www/server/php").glob("*/bin/php")) if Path("/www/server/php").exists() else []
    if shutil.which("php"):
        php_bins.append(Path(shutil.which("php")))
    for php in php_bins:
        if php.exists():
            versions["php:" + str(php)] = command_version([str(php), "-v"])
    versions["panel_detected"] = {
        "aapanel_or_bt": Path("/www/server/panel").exists(),
        "1panel": Path("/opt/1panel").exists(),
    }
    return versions


def ports_audit():
    result = run(["ss", "-H", "-lnt"], timeout=15)
    findings = []
    listeners = []
    if not result["ok"]:
        return [], [], "ss unavailable: " + result["error"]
    for line in result["stdout"].splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        address = parts[3]
        m = re.search(r":(\d+)$", address)
        if not m:
            continue
        port = int(m.group(1))
        bind = address[:m.start()].strip("[]")
        is_all = bind in ("0.0.0.0", "::", "*")
        if port in SENSITIVE_PORTS:
            listeners.append({"port": port, "bind": bind,
                              "service_hint": SENSITIVE_PORTS[port]})
            if is_all:
                findings.append(finding("configuration", "HIGH",
                    f"Sensitive port {port} listening on all interfaces",
                    f"{SENSITIVE_PORTS[port]}; {address} (firewall reachability not checked)",
                    "Restrict bind address, firewall rules, and upstream network ACLs."))
    return listeners, findings, None


def docker_audit():
    if not shutil.which("docker"):
        return [], [], [], "Docker CLI unavailable"
    result = run(["docker", "ps", "-q", "--no-trunc"], timeout=25)
    if not result["ok"]:
        return [], [], [], "Docker daemon inaccessible: " + result["error"]
    containers, images, findings = [], set(), []
    for cid in result["stdout"].splitlines()[:200]:
        inspected = run(["docker", "inspect", "--format",
                         "{{json .HostConfig}}", cid], timeout=25)
        metadata = run(["docker", "inspect", "--format",
                        "{{.Name}}|{{.Config.Image}}", cid], timeout=25)
        if not inspected["ok"] or not metadata["ok"]:
            findings.append(finding("scan_error", "UNKNOWN", "Docker inspect failed",
                                    cid[:12], "Check Docker daemon permissions."))
            continue
        try:
            host = json.loads(inspected["stdout"])
        except ValueError:
            continue
        name, sep, image = metadata["stdout"].strip().partition("|")
        if not sep:
            continue
        if image:
            images.add(image)
        containers.append({"name": name.lstrip("/"), "image": image})
        if host.get("Privileged"):
            findings.append(finding("configuration", "HIGH", "Privileged container",
                                    name, "Run container without privileged=true."))
        binds = host.get("Binds") or []
        if any("/var/run/docker.sock" in str(item) for item in binds):
            findings.append(finding("configuration", "CRITICAL", "Docker socket bind mount",
                                    name, "Remove docker.sock bind from untrusted services."))
        network = host.get("NetworkMode")
        if network == "host":
            findings.append(finding("configuration", "MEDIUM", "Host network container",
                                    name, "Verify that host networking is required."))
        if host.get("PidMode") == "host":
            findings.append(finding("configuration", "HIGH", "Host PID namespace",
                                    name, "Avoid pid: host unless strictly necessary."))
    return containers, sorted(images), findings, None


def parse_trivy(payload, target):
    issues = []
    for result in payload.get("Results") or []:
        for item in result.get("Vulnerabilities") or []:
            issues.append({
                "id": item.get("VulnerabilityID", ""),
                "severity": item.get("Severity", "UNKNOWN").upper(),
                "package": item.get("PkgName", ""),
                "installed": item.get("InstalledVersion", ""),
                "fixed": item.get("FixedVersion", ""),
                "target": target,
            })
    return issues


def trivy_scan(mode, target, timeout):
    if not shutil.which("trivy"):
        return None, "Trivy not installed"
    # Local temporary file avoids huge stdout and will be deleted on exit.
    with tempfile.TemporaryDirectory(prefix="cve-guard-") as temp:
        outfile = str(Path(temp) / "result.json")
        cmd = ["trivy", mode, "--quiet", "--scanners", "vuln", "--format", "json",
               "--output", outfile, "--timeout", f"{timeout}s", target]
        if mode == "rootfs":
            for directory in ("/proc", "/sys", "/dev", "/run", "/var/lib/docker",
                              "/var/lib/containerd", "/var/lib/cve-guard"):
                cmd.extend(["--skip-dirs", directory])
        result = run(cmd, timeout=timeout + 25)
        if not result["ok"]:
            return None, ("Trivy exit " + str(result["returncode"]) +
                          ": " + result["error"])[:1200]
        try:
            data = json.loads(Path(outfile).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return None, f"Invalid Trivy report: {exc}"
        return parse_trivy(data, target), None


def audit_dependencies(app, timeout):
    path = Path(app["path"]).expanduser().resolve()
    name = app.get("name") or path.name
    findings, errors, vulns = [], [], []
    if not path.is_dir():
        return [], [], [f"{name}: directory not found: {path}"]
    if (path / "package-lock.json").is_file() and shutil.which("npm"):
        result = run(["npm", "audit", "--json", "--omit=dev"], cwd=str(path), timeout=timeout)
        try:
            data = json.loads(result["stdout"])
            for advisory_id, advisory in (data.get("vulnerabilities") or {}).items():
                severity = str(advisory.get("severity", "UNKNOWN")).upper()
                via = advisory.get("via") or []
                cves = sorted({c for v in via if isinstance(v, dict)
                               for c in (v.get("cwe") or [])})
                vulns.append({"id": "npm:" + advisory_id, "severity": severity,
                              "package": advisory_id, "installed": "",
                              "fixed": "", "target": name,
                              "advisory": advisory.get("fixAvailable", False),
                              "cwe": cves})
        except (ValueError, TypeError):
            errors.append(f"{name}: npm audit returned non-JSON or failed: {result['error']}")
    elif (path / "package-lock.json").exists():
        errors.append(f"{name}: npm CLI not installed")
    if (path / "composer.lock").is_file() and shutil.which("composer"):
        result = run(["composer", "audit", "--locked", "--format=json", "--no-interaction"],
                     cwd=str(path), timeout=timeout)
        try:
            data = json.loads(result["stdout"])
            for package, entries in (data.get("advisories") or {}).items():
                for v in entries:
                    vulns.append({"id": v.get("cve") or v.get("advisoryId") or "unknown",
                                  "severity": str(v.get("severity") or "UNKNOWN").upper(),
                                  "package": package, "installed": "", "fixed": "",
                                  "target": name})
        except (ValueError, TypeError):
            errors.append(f"{name}: composer audit failed: {result['error']}")
    elif (path / "composer.lock").exists():
        errors.append(f"{name}: Composer not installed")
    return findings, vulns, errors


def make_report(config):
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    report = {"timestamp_utc": now, "host": get_os(), "versions": inventory(),
              "listeners": [], "containers": [], "vulnerabilities": [],
              "findings": [], "scan_errors": [], "scan_coverage": []}
    # Vendor backports may exist; report unsupported upstream runtimes for manual verification.
    for label, value in report["versions"].items():
        if not label.startswith("php:"):
            continue
        match = re.search(r"PHP\s+(\d+)\.(\d+)\.", str(value))
        if match and (int(match.group(1)) < 8 or
                      (int(match.group(1)) == 8 and int(match.group(2)) < 2)):
            report["findings"].append(finding("maintenance", "HIGH",
                "PHP upstream branch out of support", f"{label}: {value}",
                "Check vendor backported security fixes; migrate to a supported PHP branch after compatibility testing."))
    listeners, findings, err = ports_audit()
    report["listeners"] = listeners
    report["findings"].extend(findings)
    if err:
        report["scan_errors"].append(err)
    else:
        report["scan_coverage"].append("TCP listening socket audit")
    containers, images, findings, err = docker_audit()
    report["containers"] = containers
    report["findings"].extend(findings)
    if err:
        report["scan_errors"].append(err)
    else:
        report["scan_coverage"].append("Docker configuration inventory")
    timeout = max(30, min(int(config.get("timeout_seconds", 360)), 3600))
    if config.get("scan_docker_images", True):
        if not images:
            report["scan_errors"].append("Docker image scan: no accessible running Docker images")
        for image in images[:40]:
            vulns, err = trivy_scan("image", image, timeout)
            if err:
                report["scan_errors"].append(f"Docker image {image}: {err}")
            else:
                report["scan_coverage"].append("image: " + image)
                report["vulnerabilities"].extend(vulns)
    if config.get("scan_host_rootfs", False):
        vulns, err = trivy_scan("rootfs", "/", timeout)
        if err:
            report["scan_errors"].append("Host rootfs: " + err)
        else:
            report["scan_coverage"].append("host rootfs")
            report["vulnerabilities"].extend(vulns)
    for app in config["applications"]:
        path = app["path"]
        vulns, err = trivy_scan("fs", path, timeout)
        if err:
            report["scan_errors"].append(f"Application {app.get('name', path)}: {err}")
        else:
            report["scan_coverage"].append("application: " + str(path))
            report["vulnerabilities"].extend(vulns)
        findings, vulns, errors = audit_dependencies(app, timeout)
        report["findings"].extend(findings)
        report["vulnerabilities"].extend(vulns)
        report["scan_errors"].extend(errors)
    # apt output is evidence of available upgrades, not CVE attribution.
    if shutil.which("apt"):
        result = run(["apt", "list", "--upgradable"], timeout=35)
        if result["ok"]:
            packages = [ln.split("/", 1)[0] for ln in result["stdout"].splitlines()
                        if "/" in ln and not ln.startswith("Listing")]
            report["packages_upgradable"] = packages[:300]
            if packages:
                report["findings"].append(finding("maintenance", "MEDIUM",
                    "APT upgrades available", f"{len(packages)} upgradeable packages",
                    "Review apt policies and apply Ubuntu security updates."))
        else:
            report["scan_errors"].append("apt list: " + result["error"])
    return report


def markdown_report(report):
    counts = {s: 0 for s in SEVERITIES}
    for v in report["vulnerabilities"]:
        sev = v.get("severity", "UNKNOWN")
        counts[sev if sev in counts else "UNKNOWN"] += 1
    lines = [
        "# CVE Guard — 本地巡检结果", "",
        f"- 时间 (UTC): {report['timestamp_utc']}",
        f"- 系统: {report['host']['distribution']}",
        f"- 内核: {report['host']['kernel']}",
        f"- 漏洞数: " + ", ".join(f"{s}={n}" for s, n in counts.items()),
        f"- 配置/维护发现: {len(report['findings'])}",
        f"- 未完成检查: {len(report['scan_errors'])}",
        "", "## 扫描覆盖", "",
    ]
    lines += ["- " + v for v in report["scan_coverage"]] or ["- 尚未成功进行任何扫描"]
    lines += ["", "## 未完成或错误", ""]
    lines += ["- " + str(v).replace("\n", " ") for v in report["scan_errors"]] or ["- 无"]
    lines += ["", "## 配置风险", ""]
    for f in report["findings"]:
        lines.append(f"- **{f['severity']}** {f['title']} — {f['evidence']}；建议：{f['remediation']}")
    if not report["findings"]:
        lines.append("- 在已覆盖的检查中未发现配置风险；不等于系统安全。")
    lines += ["", "## 漏洞（最多展示前 150 条，完整数据见 JSON）", ""]
    priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    for v in sorted(report["vulnerabilities"],
                    key=lambda v: priority.get(v.get("severity"), 5))[:150]:
        fields = [v.get("id"), v.get("package"), v.get("installed"),
                  v.get("fixed"), v.get("target")]
        cleaned = [str(value or "-").replace("|", "/").replace("\n", " ") for value in fields]
        lines.append(f"- **{v.get('severity', 'UNKNOWN')}** {cleaned[0]} | "
                     f"包: {cleaned[1]} | 已装: {cleaned[2]} | 修复: {cleaned[3]} | 来源: {cleaned[4]}")
    if not report["vulnerabilities"]:
        lines.append("- 未发现或未成功扫描漏洞；请核对上方扫描覆盖和错误，不可直接视为无漏洞。")
    lines += ["", "> 报告仅保存在本机。监听所有地址不代表端口已从公网可访问。", ""]
    return "\n".join(lines)


def save_reports(report, outdir):
    outdir = Path(outdir)
    outdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(outdir, 0o700)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    paths = []
    for suffix, contents in [
        (".json", json.dumps(report, ensure_ascii=False, indent=2) + "\n"),
        (".md", markdown_report(report)),
    ]:
        path = outdir / ("scan-" + stamp + suffix)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(contents)
        paths.append(str(path))
    return paths


def main():
    parser = argparse.ArgumentParser(description="Read-only local VPS CVE/config audit")
    parser.add_argument("--config", default=None, help="local config JSON")
    parser.add_argument("--output-dir", default="/var/lib/cve-guard/reports")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        report = make_report(config)
        paths = save_reports(report, args.output_dir)
    except (OSError, ValueError) as exc:
        print(f"CVE Guard failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"reports": paths, "vulnerabilities": len(report["vulnerabilities"]),
                      "findings": len(report["findings"]),
                      "scan_errors": len(report["scan_errors"])}, ensure_ascii=False))
    return 0 if not report["scan_errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
