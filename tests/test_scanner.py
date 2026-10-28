"""Offline CLI regression tests; no target requests are sent."""

import io
import itertools
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from scanner import check


class ExitCodeTests(unittest.TestCase):
    def setUp(self):
        # Fail immediately if a test accidentally reaches the network layer.
        network_patch = patch.object(
            check.socket, "create_connection",
            side_effect=AssertionError("Network access is forbidden in CLI tests"),
        )
        self.network = network_patch.start()
        self.addCleanup(network_patch.stop)

    def run_cli(self, verdicts, *options):
        targets = [f"http://target-{i}.invalid" for i in range(len(verdicts))]
        results = {
            target: {
                "target": target, "verdict": verdict, "confidence": "LOW",
                "version": None, "sapi": None, "checks": {}, "chains": [],
                "recommendation": "", "error": None,
            }
            for target, verdict in zip(targets, verdicts)
        }
        argv = ["check.py"]
        if len(targets) == 1:
            argv.append(targets[0])
        else:
            argv.extend(["--targets", "-", "--threads", "2"])
        argv.extend(options)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(check.sys, "argv", argv), \
                patch.object(check.sys, "stdin", io.StringIO("\n".join(targets))), \
                patch.object(check, "scan", side_effect=lambda url, **kw: results[url]) as scan, \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = check.main()
        self.assertEqual(scan.call_count, len(targets))
        self.assertEqual({call[0][0] for call in scan.call_args_list}, set(targets))
        self.network.assert_not_called()
        return code, stdout.getvalue()

    def test_single_target_exit_codes(self):
        for verdict, expected in (
            ("VULNERABLE", 0), ("LIKELY_VULNERABLE", 0),
            ("PATCHED", 1), ("UNKNOWN", 2), ("ERROR", 2),
        ):
            with self.subTest(verdict=verdict):
                code, output = self.run_cli([verdict], "--json")
                self.assertEqual(code, expected)
                self.assertEqual(json.loads(output)["verdict"], verdict)

    def test_only_patched_batch_returns_one(self):
        code, _ = self.run_cli(["PATCHED", "PATCHED"], "--json")
        self.assertEqual(code, 1)

    def test_inconclusive_batches_return_two_regardless_of_order(self):
        for verdicts in (
            ("PATCHED", "UNKNOWN"), ("PATCHED", "ERROR"),
            ("PATCHED", "UNKNOWN", "ERROR"),
            ("UNKNOWN", "ERROR"), ("UNKNOWN", "UNKNOWN"), ("ERROR", "ERROR"),
        ):
            for order in set(itertools.permutations(verdicts)):
                with self.subTest(verdicts=order):
                    code, output = self.run_cli(order, "--json")
                    self.assertEqual(code, 2)
                    self.assertCountEqual(
                        [r["verdict"] for r in json.loads(output)], order,
                    )

    def test_vulnerable_findings_take_precedence(self):
        for vulnerable in ("VULNERABLE", "LIKELY_VULNERABLE"):
            for other in ("PATCHED", "UNKNOWN", "ERROR"):
                for order in ((vulnerable, other), (other, vulnerable)):
                    with self.subTest(verdicts=order):
                        code, _ = self.run_cli(order, "--json")
                        self.assertEqual(code, 0)
            with self.subTest(verdict=vulnerable, batch="mixed"):
                code, _ = self.run_cli(
                    ["PATCHED", "UNKNOWN", "ERROR", vulnerable], "--json",
                )
                self.assertEqual(code, 0)

    def test_text_output_preserves_inconclusive_exit_code(self):
        code, output = self.run_cli(["PATCHED", "ERROR"])
        self.assertEqual(code, 2)
        self.assertIn("Verdict: PATCHED", output)
        self.assertIn("Verdict: ERROR", output)

    def test_quiet_output_preserves_inconclusive_exit_code(self):
        code, output = self.run_cli(["PATCHED", "UNKNOWN"], "--quiet")
        self.assertEqual(code, 2)
        self.assertEqual(output, "")

    def test_quiet_output_preserves_vulnerable_exit_code(self):
        code, output = self.run_cli(["PATCHED", "VULNERABLE"], "--quiet")
        self.assertEqual(code, 0)
        self.assertIn("Verdict: VULNERABLE", output)
        self.assertNotIn("Verdict: PATCHED", output)


if __name__ == "__main__":
    unittest.main()
