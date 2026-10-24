import unittest

from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from risk import classify, enrich, presentation_key


class RiskTests(unittest.TestCase):
    def test_old_kernel_modules_are_not_reported_as_running(self):
        old = {"target": "/", "package": "linux-modules-6.8.0-138-generic",
               "id": "CVE-2026-1234", "severity": "CRITICAL"}
        self.assertEqual(classify(old, "6.8.0-147-generic"), "inactive_kernel")

    def test_running_kernel_modules_require_vendor_review(self):
        current = {"target": "/", "package": "linux-modules-6.8.0-147-generic"}
        self.assertEqual(classify(current, "6.8.0-147-generic"), "running_kernel")
        self.assertEqual(classify(current, "not-a-kernel"), "kernel_version_unknown")

    def test_headers_tools_and_libc_dev_are_not_running_kernel(self):
        for package in ("linux-headers-6.8.0-147-generic",
                        "linux-tools-6.8.0-138",
                        "linux-libc-dev"):
            with self.subTest(package=package):
                self.assertEqual(classify({"target": "/", "package": package},
                                          "6.8.0-147-generic"), "kernel_build_package")

    def test_container_vulnerability_keeps_regular_priority(self):
        row = {"target": "ghcr.io/example/site:new", "package": "openssl"}
        self.assertEqual(classify(row, "6.8.0-147-generic"), "installed_component")

    def test_matches_not_dropped_and_categories_are_transparent(self):
        raw = [
            {"target": "/", "package": "linux-modules-6.8.0-138-generic",
             "id": "CVE-2026-1234", "severity": "CRITICAL"},
            {"target": "/", "package": "linux-modules-6.8.0-147-generic",
             "id": "CVE-2026-1234", "severity": "CRITICAL"},
            {"target": "/", "package": "linux-headers-6.8.0-147",
             "id": "CVE-2026-1234", "severity": "CRITICAL"},
            {"target": "image:latest", "package": "openssl",
             "id": "CVE-2026-9999", "severity": "HIGH"},
        ]
        report = {"host": {"kernel": "6.8.0-147-generic"}, "vulnerabilities": raw}
        enrich(report)
        self.assertEqual(len(report["vulnerabilities"]), 4)
        summary = report["risk_summary"]
        self.assertEqual(summary["package_matches"]["inactive_kernel"], 1)
        self.assertEqual(summary["package_matches"]["running_kernel"], 1)
        self.assertEqual(summary["package_matches"]["kernel_build_package"], 1)
        self.assertEqual(summary["package_matches"]["installed_component"], 1)
        self.assertLess(presentation_key(raw[3]), presentation_key(raw[0]))


if __name__ == "__main__":
    unittest.main()
