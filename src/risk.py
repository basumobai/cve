"""Conservative CVE match triage, not an exploitability verdict.

All matches remain in the raw report. Classification only affects presentation.
"""
import re

CATEGORIES = ("installed_component", "running_kernel", "kernel_build_package",
              "inactive_kernel", "kernel_version_unknown")
LABELS = {
    "installed_component": "已安装组件（需核实暴露面）",
    "running_kernel": "当前运行内核相关（需核对 Ubuntu 安全公告）",
    "kernel_build_package": "内核头文件/开发工具（非运行内核证据）",
    "inactive_kernel": "非当前运行内核包（仍已安装）",
    "kernel_version_unknown": "内核版本无法对应（需人工核实）",
}
KERNEL_VERSION = re.compile(r"(\d+\.\d+\.\d+-\d+)")
KERNEL_RUNTIME = re.compile(
    r"^linux-(?:image|image-unsigned|modules|modules-extra)-\d+\.\d+\.\d+-\d+"
)
KERNEL_DEVELOPMENT = re.compile(
    r"^linux-(?:headers|tools|cloud-tools)-\d+\.\d+\.\d+-\d+"
)
OTHER_DEVELOPMENT = {
    "linux-libc-dev", "linux-tools-common", "linux-cloud-tools-common",
}


def classify(issue, running_kernel):
    """Classify an installed package match without claiming a CVE is fixed."""
    package = str(issue.get("package") or "")
    target = str(issue.get("target") or "")
    if target != "/":
        return "installed_component"
    if package in OTHER_DEVELOPMENT or KERNEL_DEVELOPMENT.match(package):
        return "kernel_build_package"
    if not KERNEL_RUNTIME.match(package):
        return "installed_component"
    installed = KERNEL_VERSION.search(package)
    current = KERNEL_VERSION.search(str(running_kernel or ""))
    if not installed or not current:
        return "kernel_version_unknown"
    return "running_kernel" if installed.group(1) == current.group(1) else "inactive_kernel"


def enrich(report):
    """Attach triage metadata while retaining every original CVE match."""
    kernel = (report.get("host") or {}).get("kernel", "")
    counts = {name: 0 for name in CATEGORIES}
    unique_ids = {name: set() for name in CATEGORIES}
    for issue in report.get("vulnerabilities", []):
        category = classify(issue, kernel)
        issue["risk_category"] = category
        counts[category] += 1
        identifier = str(issue.get("id") or "").strip()
        if identifier:
            unique_ids[category].add(identifier)
    report["risk_summary"] = {
        "kernel_checked": str(kernel),
        "package_matches": counts,
        "unique_ids_by_category": {
            key: len(values) for key, values in unique_ids.items()
        },
        "note": ("Categories represent package/runtime context, not confirmed "
                 "exploitability or vendor patch status. IDs may appear in multiple categories."),
    }
    return report


def presentation_key(issue):
    severity = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                "LOW": 3, "UNKNOWN": 4}
    category = issue.get("risk_category", "installed_component")
    category_priority = {
        "installed_component": 0, "running_kernel": 1,
        "kernel_version_unknown": 2, "kernel_build_package": 3,
        "inactive_kernel": 4,
    }
    return (category_priority.get(category, 5),
            severity.get(str(issue.get("severity", "")).upper(), 4),
            str(issue.get("target", "")), str(issue.get("package", "")),
            str(issue.get("id", "")))
