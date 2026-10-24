import importlib.util
from pathlib import Path
import tempfile
import unittest

source = Path(__file__).resolve().parents[1] / "src" / "cve_guard.py"
spec = importlib.util.spec_from_file_location("cve_guard", source)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def test_trivy_conversion(self):
        payload = {"Results": [
            {"Target": "image", "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2025-1234", "Severity": "HIGH",
                 "PkgName": "example", "InstalledVersion": "1", "FixedVersion": "2"}
            ]}
        ]}
        rows = guard.parse_trivy(payload, "image:latest")
        self.assertEqual(rows[0]["id"], "CVE-2025-1234")
        self.assertEqual(rows[0]["fixed"], "2")
        self.assertEqual(rows[0]["target"], "image:latest")

    def test_missing_scan_not_safe(self):
        r = {"timestamp_utc": "2026-10-24T00:00:00+00:00",
             "host": {"distribution": "Ubuntu", "kernel": "generic"},
             "scan_coverage": [], "scan_errors": ["Trivy not installed"],
             "vulnerabilities": [], "findings": []}
        md = guard.markdown_report(r)
        self.assertIn("Trivy not installed", md)
        self.assertIn("不等于", md)

    def test_reports_private(self):
        report = {"timestamp_utc": "2026-10-24T00:00:00+00:00",
                  "host": {"distribution": "Ubuntu", "kernel": "generic"},
                  "scan_coverage": [], "scan_errors": [],
                  "vulnerabilities": [], "findings": []}
        with tempfile.TemporaryDirectory() as d:
            paths = guard.save_reports(report, Path(d) / "reports")
            self.assertEqual(len(paths), 2)
            for file in paths:
                self.assertEqual(Path(file).stat().st_mode & 0o777, 0o600)
            self.assertEqual((Path(d) / "reports").stat().st_mode & 0o777, 0o700)

    def test_config_validation(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text('{"applications":[42]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                guard.load_config(p)

    def test_command_no_shell(self):
        result = guard.run(["/bin/echo", "hello"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["stdout"].strip(), "hello")


if __name__ == "__main__":
    unittest.main()
