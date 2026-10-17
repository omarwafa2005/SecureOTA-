"""Quality tests for the phase package itself (NFR-01, NFR-03).

Docstring format: <test ID> | <threat IDs or -> | <requirement IDs>.
"""
import unittest
from pathlib import Path

import run_all
from tools import bench_verify

PHASE2 = Path(__file__).resolve().parent.parent


class QualityTests(unittest.TestCase):

    def test_QT_03_verification_latency_is_measured_for_defined_sizes(self):
        """QT-03 | - | NFR-03"""
        small = {"64KiB": 64 * 1024, "1MiB": 1024 * 1024}      # full sizes run in run_all
        rows = bench_verify.measure(repeat=2, sizes=small)
        self.assertEqual([r["size"] for r in rows], ["64KiB", "1MiB"])
        for r in rows:
            self.assertGreater(r["pipeline_median_ms"], 0)
            self.assertLessEqual(r["pipeline_median_ms"], r["pipeline_max_ms"])
            self.assertTrue(r["python"] and r["machine"])
        self.assertEqual(list(bench_verify.SIZES), ["64KiB", "1MiB", "16MiB"])

    def test_QT_04_documented_commands_reproduce_the_package(self):
        """QT-04 | - | NFR-01"""
        readme = (PHASE2 / "README.md").read_text(encoding="utf-8")
        self.assertIn("python run_all.py", readme)
        self.assertIn("pip install -r requirements.txt", readme)
        for _title, cmd, _log in run_all.STEPS:
            script = next((c for c in cmd if c.endswith(".py")), None)
            if script:
                self.assertTrue((PHASE2 / script).is_file(), script)
                self.assertIn(Path(script).name, readme, f"{script} not documented in README")
        reqs = (PHASE2.parent / "requirements.txt").read_text(encoding="utf-8")
        for package in ("cryptography", "fastapi", "httpx"):
            self.assertIn(package, reqs)
