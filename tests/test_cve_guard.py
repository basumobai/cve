import importlib.util
from pathlib import Path
import tempfile
import unittest
import sys
from unittest import mock

source = Path(__file__).resolve().parents[1] / "src" / "cve_guard.py"
sys.path.insert(0, str(source.parent))
spec = importlib.util.spec_from_file_location("cve_guard", source)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def test_auto_discover_wwwroot_and_nested_apps(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "www" / "wwwroot"
            root.mkdir(parents=True)
            (root / "php-site").mkdir()
            (root / "php-site" / "artisan").touch()
            (root / "php-site" / "composer.lock").write_text("{}", encoding="utf-8")
            (root / "php-site" / "node_modules").mkdir()
            (root / "php-site" / "node_modules" / "untrusted").mkdir()
            (root / "php-site" / "node_modules" / "untrusted" / "package-lock.json").touch()
            (root / "node-site" / "frontend").mkdir(parents=True)
            (root / "node-site" / "frontend" / "pnpm-lock.yaml").touch()
            (root / "static-site").mkdir()
            (root / "static-site" / "index.html").touch()
            sites, warnings = guard.discover_websites([str(root)])
            self.assertEqual({s["name"] for s in sites},
                             {"php-site", "node-site", "static-site"})
            php = next(s for s in sites if s["name"] == "php-site")
            node = next(s for s in sites if s["name"] == "node-site")
            self.assertIn("Laravel", php["technologies"])
            self.assertIn("Node.js", node["technologies"])
            self.assertEqual(len(php["projects"]), 1)
            self.assertEqual(len(node["projects"]), 1)
            self.assertEqual(warnings, [])

    def test_discovery_does_not_follow_site_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "wwwroot"
            root.mkdir()
            outside = Path(temp) / "outside"
            outside.mkdir()
            (outside / "composer.lock").touch()
            (root / "outside-link").symlink_to(outside, target_is_directory=True)
            (root / "site").mkdir()
            sites, warnings = guard.discover_websites([str(root)])
            self.assertEqual([s["name"] for s in sites], ["site"])
            self.assertTrue(any("symlink" in msg for msg in warnings))

    def test_discovery_limit_and_missing_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "wwwroot"
            root.mkdir()
            for name in ("a", "b", "c"):
                (root / name).mkdir()
            sites, warnings = guard.discover_websites(
                [str(root), str(root / "missing")], max_sites=2)
            self.assertEqual(len(sites), 2)
            self.assertTrue(any("limit" in msg for msg in warnings))

    def test_default_config_enables_www_scanning(self):
        config = guard.load_config(None)
        self.assertTrue(config["auto_discover_websites"])
        self.assertTrue(config["scan_web_files"])
        self.assertIn("/www/wwwroot", config["web_roots"])

    def test_report_scans_auto_discovered_site_and_nested_lockfiles(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "wwwroot"
            app = root / "example.com"
            app.mkdir(parents=True)
            (app / "composer.lock").write_text("{}", encoding="utf-8")
            config = guard.load_config(None)
            config.update({
                "web_roots": [str(root)],
                "scan_host_rootfs": False,
                "scan_docker_images": False,
                "applications": [],
            })
            with mock.patch.object(guard, "get_os", return_value={
                "distribution": "Ubuntu", "kernel": "generic"
            }), mock.patch.object(guard, "inventory", return_value={}), \
                 mock.patch.object(guard, "ports_audit", return_value=([], [], None)), \
                 mock.patch.object(guard, "docker_audit", return_value=([], [], [], None)), \
                 mock.patch.object(guard, "trivy_scan", return_value=([], None)) as scanner, \
                 mock.patch.object(guard, "audit_dependencies", return_value=([], [], [])) as dependencies, \
                 mock.patch.object(guard.shutil, "which", return_value=None):
                report = guard.make_report(config)
            self.assertEqual(len(report["websites"]), 1)
            self.assertEqual(report["websites"][0]["name"], "example.com")
            self.assertTrue(any("website fs:" in s for s in report["scan_coverage"]))
            scanner.assert_called_once()
            self.assertEqual(scanner.call_args.args[:2], ("fs", str(app)))
            dependencies.assert_called_once()
            self.assertEqual(dependencies.call_args.args[0]["path"], str(app))

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
