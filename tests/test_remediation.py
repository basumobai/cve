import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import importlib.util
import sys

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))
spec = importlib.util.spec_from_file_location("remediation", SRC / "remediation.py")
rem = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rem)


class RemediationTests(unittest.TestCase):
    def test_plan_never_marks_fixes_automatic(self):
        data = {"timestamp_utc": "2026-10-24T10:00:00Z",
                "vulnerabilities": [
                    {"id": "CVE-2026-1", "package": "example",
                     "target": "/www/wwwroot/site", "severity": "HIGH",
                     "installed": "1", "fixed": "2"}],
                "findings": [], "scan_errors": ["Trivy unavailable"]}
        plan = rem.build_plan(data, Path("/var/lib/cve-guard/reports/scan-test.json"))
        self.assertTrue(plan["scan_incomplete"])
        self.assertFalse(plan["items"][0]["automated"])
        self.assertIn("不会自动升级", rem.render(plan))

    def test_generate_plan_private_and_no_mutations(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            reports = root / "reports"
            reports.mkdir()
            (reports / "scan-20261024T100000000000Z.json").write_text(
                json.dumps({"timestamp_utc": "today", "vulnerabilities": [],
                            "findings": [], "scan_errors": []}))
            with mock.patch.object(rem, "run") as runner:
                path = rem.generate(reports, root / "plans")
            runner.assert_not_called()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertTrue(path.with_suffix(".md").exists())

    def test_apply_requires_interactive_terminal(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(rem.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(ValueError, "非交互"):
                    rem.apply_apt(Path(d), interactive=False)

    def test_apply_rejects_invalid_packages(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "apt-prepared.json"
            path.write_text(json.dumps({
                "schema": 1,
                "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "packages": ["nginx;touch /tmp/pwn"],
                "simulation_sha256": "abc"}))
            with mock.patch.object(rem.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(ValueError, "非法"):
                    rem.apply_apt(Path(d), interactive=True)

    def test_apply_rejects_changed_apt_simulation(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "apt-prepared.json"
            path.write_text(json.dumps({
                "schema": 1,
                "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "packages": ["nginx"],
                "simulation_sha256": hashlib.sha256(b"original").hexdigest()}))
            runner = mock.Mock(return_value=mock.Mock(
                returncode=0, stdout="changed", stderr=""))
            with mock.patch.object(rem.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(ValueError, "已变化"):
                    rem.apply_apt(Path(d), interactive=True, runner=runner)
            self.assertEqual(runner.call_count, 1)

    def test_apply_refuses_without_exact_phrase(self):
        with tempfile.TemporaryDirectory() as d:
            simulation = "Inst nginx [1] (2 Ubuntu:24.04)"
            path = Path(d) / "apt-prepared.json"
            path.write_text(json.dumps({
                "schema": 1,
                "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "packages": ["nginx"],
                "simulation_sha256": hashlib.sha256(simulation.encode()).hexdigest()}))
            runner = mock.Mock(return_value=mock.Mock(
                returncode=0, stdout=simulation, stderr=""))
            with mock.patch.object(rem.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(ValueError, "未获批准"):
                    rem.apply_apt(Path(d), input_fn=lambda _: "yes",
                                  interactive=True, runner=runner)
            self.assertEqual(runner.call_count, 1)


if __name__ == "__main__":
    unittest.main()
