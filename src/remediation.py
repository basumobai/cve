#!/usr/bin/env python3
"""Generate advisory remediation plans; apply only approved Ubuntu APT upgrades."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REPORTS = Path("/var/lib/cve-guard/reports")
PLANS = Path("/var/lib/cve-guard/plans")
APT_NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def write_private(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                     dir=str(path.parent), prefix=".tmp-",
                                     delete=False) as handle:
        tmp = Path(handle.name)
        os.chmod(tmp, 0o600)
        try:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    os.replace(tmp, path)


def latest_report(directory=REPORTS):
    candidates = sorted(p for p in directory.glob("scan-*.json")
                        if p.is_file() and not p.is_symlink())
    if not candidates:
        raise ValueError("没有扫描报告。请先执行 sudo cve scan")
    return candidates[-1]


def load_report(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("报告不存在或为符号链接")
    with path.open(encoding="utf-8") as handle:
        report = json.load(handle)
    if not isinstance(report, dict) or not isinstance(report.get("vulnerabilities"), list):
        raise ValueError("报告格式无效")
    return report


def build_plan(report, source):
    items, seen = [], set()
    for issue in report.get("vulnerabilities", []):
        if not isinstance(issue, dict):
            continue
        identity = (str(issue.get("target", "")), str(issue.get("package", "")),
                    str(issue.get("id", "")), str(issue.get("installed", "")))
        if identity in seen:
            continue
        seen.add(identity)
        items.append({
            "target": identity[0], "package": identity[1],
            "id": identity[2], "installed": identity[3],
            "fixed": str(issue.get("fixed", "")),
            "severity": str(issue.get("severity", "UNKNOWN")).upper(),
            "action": "人工核实供应商安全公告和兼容性，再按官方步骤升级",
            "automated": False,
        })
    for issue in report.get("findings", []):
        if not isinstance(issue, dict):
            continue
        items.append({
            "target": str(issue.get("evidence", "")), "package": "", "id": "",
            "installed": "", "fixed": "",
            "severity": str(issue.get("severity", "UNKNOWN")).upper(),
            "action": str(issue.get("remediation", "人工确认配置后修复")),
            "automated": False,
        })
    items.sort(key=lambda i: (SEVERITIES.index(i["severity"]) if i["severity"] in SEVERITIES else 4,
                              i["target"], i["package"], i["id"]))
    return {
        "schema": 1,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_report": str(source),
        "scan_timestamp_utc": str(report.get("timestamp_utc", "")),
        "scan_incomplete": bool(report.get("scan_errors")),
        "scan_errors": [str(x) for x in report.get("scan_errors", [])],
        "items": items,
        "apt": {"state": "requires_explicit_preparation_and_approval", "packages": []},
    }


def render(plan):
    lines = ["# CVE Guard 修复建议", "",
             "生成时间：" + plan["created_utc"],
             "扫描报告：" + plan["source_report"], "",
             "> 仅供审阅，不会自动升级。"]
    if plan["scan_incomplete"]:
        lines += ["", "警告：扫描未全部完成，不能把结果当作完整安全结论。"]
    lines += ["", "## 风险项（%d）" % len(plan["items"]), ""]
    for item in plan["items"]:
        lines.append("- **%s** %s | %s | %s | 已安装：%s | 修复版本：%s | 建议：%s" % (
            item["severity"], item["id"], item["package"], item["target"],
            item["installed"], item["fixed"], item["action"]))
    if not plan["items"]:
        lines.append("- 没有发现已报告的风险项，不代表不存在漏洞。")
    lines += ["", "## 处理方式", "",
              "1. 每日自动扫描并生成修复建议。",
              "2. 人工核对漏洞、维护窗口、备份和兼容性。",
              "3. Ubuntu APT 包：sudo cve prepare 查看模拟升级清单。",
              "4. 人工核对后执行 sudo cve apply，并在终端输入确认词。",
              "5. PHP、Composer、npm、Docker、数据库、宝塔软件仅给出建议，不自动修改。",
              "", "APT 升级可能重启服务；必须提前备份并安排维护窗口。"]
    return "\n".join(lines) + "\n"


def generate(report_dir=REPORTS, plan_dir=PLANS):
    source = latest_report(report_dir)
    plan = build_plan(load_report(source), source)
    output = plan_dir / source.name.replace("scan-", "plan-", 1)
    write_private(output, json.dumps(plan, ensure_ascii=False, indent=2) + "\n")
    write_private(output.with_suffix(".md"), render(plan))
    return output


def run(argv, timeout=180):
    return subprocess.run(argv, text=True, capture_output=True,
                          timeout=timeout, check=False)


def prepare_apt(plan_dir=PLANS, runner=run):
    if os.geteuid() != 0:
        raise ValueError("需要 sudo")
    if not Path("/usr/bin/apt-get").exists():
        raise ValueError("需要 Ubuntu/Debian apt-get")
    simulation = runner(["/usr/bin/apt-get", "-s", "-V", "upgrade"], timeout=120)
    if simulation.returncode:
        raise ValueError("APT 模拟升级失败：" + simulation.stderr[:400])
    packages = sorted({line.split()[1] for line in simulation.stdout.splitlines()
                       if line.startswith("Inst ") and len(line.split()) >= 2
                       and APT_NAME.fullmatch(line.split()[1])})
    prepared = {
        "schema": 1,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "simulation_sha256": hashlib.sha256(simulation.stdout.encode()).hexdigest(),
        "packages": packages,
        "warning": "包含 APT 模拟升级的全部候选包，并不保证都是安全补丁。需人工审查。",
    }
    out = plan_dir / "apt-prepared.json"
    write_private(out, json.dumps(prepared, ensure_ascii=False, indent=2) + "\n")
    return out, prepared


def apply_apt(plan_dir=PLANS, input_fn=input, runner=run, interactive=None):
    if os.geteuid() != 0:
        raise ValueError("需要 sudo")
    if interactive is None:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if not interactive:
        raise ValueError("禁止非交互式执行；必须在 SSH 终端手动确认")
    path = plan_dir / "apt-prepared.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("请先执行 sudo cve prepare")
    prepared = json.loads(path.read_text(encoding="utf-8"))
    if prepared.get("schema") != 1:
        raise ValueError("无效的准备方案")
    packages = prepared.get("packages")
    if not isinstance(packages, list) or not packages or len(packages) > 1000:
        raise ValueError("没有有效的升级候选包")
    if len(set(packages)) != len(packages) or any(
            not isinstance(pkg, str) or not APT_NAME.fullmatch(pkg) for pkg in packages):
        raise ValueError("候选包名称非法")
    created = dt.datetime.fromisoformat(prepared["created_utc"])
    age = (dt.datetime.now(dt.timezone.utc) -
           created.astimezone(dt.timezone.utc)).total_seconds()
    if created.tzinfo is None or age < 0 or age > 3600:
        raise ValueError("方案已过期，重新运行 sudo cve prepare")
    current = runner(["/usr/bin/apt-get", "-s", "-V", "upgrade"], timeout=120)
    if current.returncode:
        raise ValueError("APT 再次模拟失败：" + current.stderr[:400])
    if hashlib.sha256(current.stdout.encode()).hexdigest() != prepared.get("simulation_sha256"):
        raise ValueError("APT 候选清单已变化，请重新 prepare")
    print("即将升级这些 APT 包（不保证都是安全更新）：")
    for package in packages:
        print(" -", package)
    print("请先备份并安排维护窗口，升级可能重启网站相关服务。")
    if input_fn("输入 APPLY APT UPDATES 以批准升级：") != "APPLY APT UPDATES":
        raise ValueError("未获批准；未执行更新")
    result = runner(["/usr/bin/apt-get", "install", "--only-upgrade", "-y",
                     "--", *packages], timeout=3600)
    outcome = {"executed_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
               "packages": packages, "exit_code": result.returncode,
               "stdout_tail": result.stdout[-4000:],
               "stderr_tail": result.stderr[-4000:]}
    write_private(plan_dir / "apt-last-result.json",
                  json.dumps(outcome, ensure_ascii=False, indent=2) + "\n")
    return result.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["generate", "prepare", "apply"])
    parser.add_argument("--report-dir", type=Path, default=REPORTS)
    parser.add_argument("--plan-dir", type=Path, default=PLANS)
    args = parser.parse_args()
    try:
        if args.action == "generate":
            output = generate(args.report_dir, args.plan_dir)
            print("修复方案已生成：", output.with_suffix(".md"))
        elif args.action == "prepare":
            output, plan = prepare_apt(args.plan_dir)
            print("APT 候选方案：", output)
            print("候选包数量：", len(plan["packages"]))
            print("注意：不保证都是安全补丁，需人工核对。")
        else:
            raise SystemExit(apply_apt(args.plan_dir))
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print("CVE Guard:", exc, file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
