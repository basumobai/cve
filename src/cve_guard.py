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

from site_discovery import discover_websites
from remediation import build_plan, render, write_private
from risk import enrich, LABELS, presentation_key

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


def run(argv, timeout=25, cwd=None, output_limit=150000):
    """Run a fixed argv list; no shell, bounded output, timeouts and failures recorded."""
    try:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                              errors="replace", timeout=timeout, check=False)
        return {"ok": proc.returncode == 0, "returncode": proc.returncode,
                "stdout": proc.stdout[:output_limit], "error": proc.stderr[:1200],
                "truncated": len(proc.stdout) > output_limit}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "returncode": None, "stdout": "",
                "error": f"{type(exc).__name__}: {exc}", "truncated": False}


def finding(kind, severity, title, evidence, remediation):
    return {"kind": kind, "severity": severity, "title": title,
            "evidence": evidence, "remediation": remediation}


def load_config(path):
    default = {"applications": [], "scan_docker_images": True,
               "scan_host_rootfs": True, "timeout_seconds": 360,
               "auto_discover_websites": True, "web_roots": ["/www/wwwroot"],
               "max_websites": 100, "web_project_depth": 3,
               "max_web_projects": 250, "scan_web_files": True}
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
    if not isinstance(default["auto_discover_websites"], bool):
        raise ValueError("auto_discover_websites must be boolean")
    if not isinstance(default["scan_web_files"], bool):
        raise ValueError("scan_web_files must be boolean")
    if (not isinstance(default["web_roots"], list) or
            any(not isinstance(path, str) or not path.startswith("/")
                for path in default["web_roots"])):
        raise ValueError("web_roots must contain absolute paths")
    for key, limit in (("max_websites", 500), ("web_project_depth", 6),
                       ("max_web_projects", 1000)):
        value = default[key]
        if type(value) is not int or value < 0 or value > limit:
            raise ValueError(f"{key} must be an integer between 0 and {limit}")
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
    seen_php_paths = set()
    for php in php_bins:
        if php.exists():
            real_path = str(php.resolve())
            if real_path in seen_php_paths:
                continue
            seen_php_paths.add(real_path)
            versions["php:" + str(php)] = command_version([str(php), "-v"])
    # aaPanel/BT often install software outside PATH and APT.
    extra = {
        "bt_nginx": "/www/server/nginx/sbin/nginx",
        "bt_openresty": "/www/server/openresty/nginx/sbin/nginx",
        "bt_mysql_client": "/www/server/mysql/bin/mysql",
    }
    for name, binary in extra.items():
        if Path(binary).is_file() and os.access(binary, os.X_OK):
            versions[name] = command_version([binary, "-v" if "nginx" in name or "openresty" in name else "--version"])
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


def trivy_scan(mode, target, timeout, skip_dirs=None):
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
        for directory in (skip_dirs or []):
            cmd.extend(["--skip-dirs", str(directory)])
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
        result = run(["npm", "audit", "--json", "--omit=dev"], cwd=str(path),
                     timeout=timeout, output_limit=2000000)
        try:
            if result.get("truncated"):
                raise ValueError("npm audit JSON output exceeded limit")
            data = json.loads(result["stdout"])
            if not isinstance(data, dict) or data.get("error"):
                raise ValueError("npm audit reported an API or registry error")
            if result["returncode"] not in (0, 1):
                raise ValueError("npm audit exit code: " + str(result["returncode"]))
            advisories = data.get("vulnerabilities") or {}
            if not isinstance(advisories, dict):
                raise ValueError("npm audit unexpected vulnerabilities format")
            for advisory_id, advisory in advisories.items():
                if not isinstance(advisory, dict):
                    continue
                severity = str(advisory.get("severity", "UNKNOWN")).upper()
                via = advisory.get("via") or []
                cves = sorted({c for v in via if isinstance(v, dict)
                               for c in (v.get("cwe") or [])})
                vulns.append({"id": "npm:" + advisory_id, "severity": severity,
                              "package": advisory_id, "installed": "",
                              "fixed": "", "target": name,
                              "advisory": advisory.get("fixAvailable", False),
                              "cwe": cves})
        except (ValueError, TypeError) as exc:
            errors.append(f"{name}: npm audit incomplete: {exc}; {result['error']}")
    elif (path / "package-lock.json").exists():
        errors.append(f"{name}: npm CLI not installed")
    if (path / "composer.lock").is_file() and shutil.which("composer"):
        result = run(["composer", "--no-plugins", "audit", "--locked", "--format=json", "--no-interaction"],
                     cwd=str(path), timeout=timeout, output_limit=2000000)
        try:
            if result.get("truncated"):
                raise ValueError("composer audit JSON output exceeded limit")
            output = result["stdout"].strip()
            # Old Composer versions may print notices before JSON. Never
            # interpret missing or malformed JSON as a clean audit.
            if 'Command "audit" is not defined' in result["error"] or \
                    'Command "audit" is not defined' in output:
                raise ValueError("当前 Composer 不支持 audit 命令；需 Composer >= 2.4。仅升级 Composer CLI，不要执行 composer update")
            if not output.startswith("{"):
                raise ValueError("Composer 未输出有效 JSON；检查 Composer 版本、插件与仓库网络")
            data = json.loads(output)
            if not isinstance(data, dict) or data.get("error") or data.get("errors"):
                raise ValueError("composer audit returned errors")
            if result["returncode"] not in (0, 1):
                raise ValueError("composer audit exit code: " + str(result["returncode"]))
            advisories = data.get("advisories") or {}
            if not isinstance(advisories, dict):
                raise ValueError("composer audit unexpected advisories format")
            for package, entries in advisories.items():
                for v in entries:
                    vulns.append({"id": v.get("cve") or v.get("advisoryId") or "unknown",
                                  "severity": str(v.get("severity") or "UNKNOWN").upper(),
                                  "package": package, "installed": "", "fixed": "",
                                  "target": name})
        except (ValueError, TypeError) as exc:
            errors.append(f"{name}: composer audit incomplete: {exc}; {result['error']}")
    elif (path / "composer.lock").exists():
        errors.append(f"{name}: Composer not installed")
    return findings, vulns, errors


def distinct_vulnerabilities(rows):
    """Keep one finding for each unique package/advisory/version/target."""
    output, seen = [], set()
    for row in rows:
        key = tuple(str(row.get(field, "")) for field in
                    ("id", "package", "installed", "target"))
        if key not in seen:
            seen.add(key)
            output.append(row)
    return output


def unique_cve_counts(report):
    """Count unique advisory IDs, separately from package match records."""
    grouped = {}
    rank = {name: i for i, name in enumerate(SEVERITIES)}
    for row in report.get("vulnerabilities", []):
        identifier = str(row.get("id") or "").strip()
        if not identifier:
            continue
        severity = str(row.get("severity", "UNKNOWN")).upper()
        severity = severity if severity in rank else "UNKNOWN"
        if identifier not in grouped or rank[severity] < rank[grouped[identifier]]:
            grouped[identifier] = severity
    counts = {name: 0 for name in SEVERITIES}
    for severity in grouped.values():
        counts[severity] += 1
    return counts


def distinct_messages(messages):
    return list(dict.fromkeys(messages))


def counts_by_severity(report):
    result = {name: 0 for name in SEVERITIES}
    for vuln in report.get("vulnerabilities", []):
        severity = str(vuln.get("severity", "UNKNOWN")).upper()
        result[severity if severity in result else "UNKNOWN"] += 1
    return result


def make_report(config):
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    report = {"timestamp_utc": now, "host": get_os(), "versions": inventory(),
              "listeners": [], "containers": [], "vulnerabilities": [],
              "websites": [], "site_discovery_warnings": [],
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
        # Skip website roots only if individual website filesystem scanning is enabled.
        skip = (config.get("web_roots", [])
                if config.get("auto_discover_websites", True) and
                   config.get("scan_web_files", True) else [])
        vulns, err = trivy_scan("rootfs", "/", timeout, skip_dirs=skip)
        if err:
            report["scan_errors"].append("Host rootfs: " + err)
        else:
            report["scan_coverage"].append("host rootfs")
            report["vulnerabilities"].extend(vulns)
    apps = list(config["applications"])
    scanned_site_paths = set()
    if config.get("auto_discover_websites", True):
        sites, warnings = discover_websites(
            config.get("web_roots", ["/www/wwwroot"]),
            max_sites=config.get("max_websites", 100),
            max_depth=config.get("web_project_depth", 3),
            max_projects=config.get("max_web_projects", 250))
        report["websites"] = sites
        report["site_discovery_warnings"] = warnings
        # Skipped sites and inaccessible paths are incomplete coverage, not "secure".
        report["scan_errors"].extend("Website discovery: " + w for w in warnings)
        for site in sites:
            path = site["path"]
            if config.get("scan_web_files", True):
                skipped = [str(Path(path) / name) for name in
                           ("logs", "log", "backup", "backups", "uploads", "upload",
                            "tmp", "temp", "cache", ".git", "node_modules",
                            ".next", "vendor", "storage")]
                vulns, err = trivy_scan("fs", path, timeout, skip_dirs=skipped)
                if err:
                    report["scan_errors"].append(f"Website {site['name']} ({path}): {err}")
                else:
                    report["scan_coverage"].append("website fs: " + path)
                    report["vulnerabilities"].extend(vulns)
                    scanned_site_paths.add(str(Path(path).resolve()))
            else:
                report["scan_coverage"].append("website discovered (fs scan disabled): " + path)
            for project in site["projects"]:
                # A failed site scan must not silently mark nested dependencies covered.
                # When site filesystem scanning is disabled, scan each discovered
                # project individually rather than claiming it was scanned.
                covered = str(Path(path).resolve()) in scanned_site_paths
                apps.append({"name": f"{site['name']} / {Path(project['path']).name}",
                             "path": project["path"], "trivy": not covered})
        if not sites and not warnings:
            report["scan_coverage"].append("No website directories found in configured web roots")
    seen_apps = set()
    for app in apps:
        path = app["path"]
        if not Path(path).is_dir():
            report["scan_errors"].append(f"Application path missing/unreadable: {path}")
            continue
        canonical = str(Path(path).expanduser().resolve())
        if canonical in seen_apps:
            continue
        seen_apps.add(canonical)
        # A discovered web project is already covered by its parent site Trivy fs scan.
        # Only manual application entries need standalone Trivy scans.
        if app.get("trivy", True) and canonical not in scanned_site_paths:
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
    report["vulnerabilities"] = distinct_vulnerabilities(report["vulnerabilities"])
    report["scan_errors"] = distinct_messages(report["scan_errors"])
    return enrich(report)


def markdown_report(report):
    counts = counts_by_severity(report)
    lines = [
        "# CVE Guard — 本地巡检结果", "",
        f"- 时间 (UTC): {report['timestamp_utc']}",
        f"- 系统: {report['host']['distribution']}",
        f"- 内核: {report['host']['kernel']}",
        f"- 软件包漏洞匹配数（非独立漏洞）: " + ", ".join(f"{s}={n}" for s, n in counts.items()),
        "- 去重漏洞编号数: " + ", ".join(f"{s}={n}" for s, n in unique_cve_counts(report).items()),
        "- 注意：同一 CVE 可影响多个包；漏洞匹配不等于实际可利用。",
        "- 风险分层仅表示包与运行环境的关系，不等于已核实漏洞或已修复状态。",
        f"- 配置/维护发现: {len(report['findings'])}",
        f"- 未完成检查: {len(report['scan_errors'])}",
        "", "## 扫描覆盖", "",
    ]
    lines += ["- " + v for v in report["scan_coverage"]] or ["- 尚未成功进行任何扫描"]
    summary = report.get("risk_summary", {})
    categories = summary.get("package_matches", {})
    lines += ["", "## 风险分层（匹配条数）", ""]
    for category, label in LABELS.items():
        lines.append(f"- {label}: {categories.get(category, 0)}")
    lines += ["- 旧内核镜像/模块、开发头文件仍保留在完整 JSON；不会因此判定安全。"]
    lines += ["", "## 自动发现的网站", ""]
    for site in report.get("websites", []):
        technologies = ", ".join(site.get("technologies", [])) or "Unknown/static"
        lines.append(f"- {site['name']} | {site['path']} | 技术: {technologies} | 发现项目: {len(site['projects'])}")
    if not report.get("websites"):
        lines.append("- 未发现网站；如部署在自定义路径，需添加至 web_roots")
    lines += ["", "## 未完成或错误", ""]
    lines += ["- " + str(v).replace("\n", " ") for v in report["scan_errors"]] or ["- 无"]
    lines += ["", "## 配置风险", ""]
    for f in report["findings"]:
        lines.append(f"- **{f['severity']}** {f['title']} — {f['evidence']}；建议：{f['remediation']}")
    if not report["findings"]:
        lines.append("- 在已覆盖的检查中未发现配置风险；不等于系统安全。")
    lines += ["", "## 漏洞候选项（优先展示前 150 条，全部记录见 JSON）", ""]
    lines += ["- 先显示应用/容器及当前内核，再显示内核开发包与未运行旧内核；这只是排查顺序。"]
    for v in sorted(report["vulnerabilities"], key=presentation_key)[:150]:
        fields = [v.get("id"), v.get("package"), v.get("installed"),
                  v.get("fixed"), v.get("target")]
        cleaned = [str(value or "-").replace("|", "/").replace("\n", " ") for value in fields]
        category = LABELS.get(v.get("risk_category"), "待核实")
        lines.append(f"- **{v.get('severity', 'UNKNOWN')}** [{category}] {cleaned[0]} | "
                     f"包: {cleaned[1]} | 已装: {cleaned[2]} | 修复: {cleaned[3]} | 来源: {cleaned[4]}")
    if not report["vulnerabilities"]:
        lines.append("- 未发现或未成功扫描漏洞；请核对上方扫描覆盖和错误，不可直接视为无漏洞。")
    lines += ["", "> 报告仅保存在本机。监听所有地址不代表端口已从公网可访问。", ""]
    return "\n".join(lines)


def save_reports(report, outdir, keep=30):
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
    # Rotate only files generated by this tool; keep last N reports.
    archives = sorted(p for p in outdir.glob("scan-*.json") if p.is_file() and not p.is_symlink())
    for old in archives[:-keep]:
        for report_path in (old, old.with_suffix(".md")):
            if report_path.is_file() and not report_path.is_symlink():
                report_path.unlink()
    return paths


def main():
    parser = argparse.ArgumentParser(description="Read-only local VPS CVE/config audit")
    parser.add_argument("--config", default=None, help="local config JSON")
    parser.add_argument("--output-dir", default="/var/lib/cve-guard/reports")
    parser.add_argument("--plan-dir", default="/var/lib/cve-guard/plans")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        report = make_report(config)
        paths = save_reports(report, args.output_dir)
        # Generate a plan even if some checks were incomplete; never execute repairs.
        source = Path(paths[0])
        plan = build_plan(report, source)
        plan_path = Path(args.plan_dir) / source.name.replace("scan-", "plan-", 1)
        write_private(plan_path, json.dumps(plan, ensure_ascii=False, indent=2) + "\n")
        write_private(plan_path.with_suffix(".md"), render(plan))
        plans = sorted(p for p in plan_path.parent.glob("plan-*.json")
                       if p.is_file() and not p.is_symlink())
        for old in plans[:-30]:
            old.unlink()
            old.with_suffix(".md").unlink(missing_ok=True)
    except (OSError, ValueError) as exc:
        print(f"CVE Guard failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"reports": paths, "vulnerabilities": len(report["vulnerabilities"]),
                      "findings": len(report["findings"]),
                      "scan_errors": len(report["scan_errors"])}, ensure_ascii=False))
    # Partial probe failures remain visible; generating the report is successful.
    return 0


if __name__ == "__main__":
    sys.exit(main())
