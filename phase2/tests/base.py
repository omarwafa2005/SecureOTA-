"""Shared fixture: a fresh two-ECU bench in a temporary directory per test."""
from __future__ import annotations

import tempfile
import unittest

from vehicle.testkit import Bench


class BenchTestCase(unittest.TestCase):
    bench_kwargs: dict = {}

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.bench = Bench(self._tmp.name, **self.bench_kwargs)
        self.gw = self.bench.gateway

    @property
    def ecu_a(self):
        return self.bench.ecus["ECU-A"]

    @property
    def ecu_b(self):
        return self.bench.ecus["ECU-B"]

    def restart(self):
        self.bench.restart()
        self.gw = self.bench.gateway

    def assertRejected(self, result, reason):
        self.assertFalse(result.ok, result)
        self.assertIs(result.reason, reason)
        public = result.public()
        self.assertEqual(public["status"], "REJECTED")
        self.assertEqual(set(public), {"status", "reason", "correlation_id"})   # US-02
        self.assertTrue(public["correlation_id"])

    def assertTrustedStateUnchanged(self, before):
        """Expected rejection leaves trusted state explicitly unchanged (S1-T4)."""
        self.assertEqual(self.bench.snapshot(), before)
