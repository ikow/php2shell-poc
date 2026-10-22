"""Native adapters, reporting, and bounded offline PCAP regression tests."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from tools.native.pcap import checksum, inspect_capture, write_capture
from tools.native.modsecurity import dechunk
from tools.native.reporting import engine_report, markdown, sarif, write_reports
from tools.validate_detection import load_fixtures
from tools.validate_native import ROOT, load_cases, main, run_suite
from tools.php_version_matrix import advisory_status, run_matrix

HAS_SIGMA = importlib.util.find_spec("sigma") is not None
HAS_JSONSCHEMA = importlib.util.find_spec("jsonschema") is not None


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.case = load_fixtures(ROOT / "tests/fixtures/native/http.json")[0]

    def test_capture_checksums_framing_and_determinism(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            with patch(
                "socket.socket", side_effect=AssertionError("No network allowed")
            ):
                write_capture(path, self.case["request"], self.case["response"], 3)
            first = path.read_bytes()
            self.assertGreater(inspect_capture(path)["packets"], 20)
            offset = 24
            while offset < len(first):
                _, _, size, _ = struct.unpack("<IIII", first[offset : offset + 16])
                offset += 16
                frame = first[offset : offset + size]
                ip, tcp = frame[14:34], frame[34:]
                self.assertEqual(checksum(ip), 0)
                self.assertEqual(struct.unpack("!H", ip[2:4])[0], len(frame) - 14)
                pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
                self.assertEqual(checksum(pseudo + tcp), 0)
                offset += size
            write_capture(path, self.case["request"], self.case["response"], 3)
            self.assertEqual(path.read_bytes(), first)

    def test_capture_rejects_malformed_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            for data in (
                b"",
                b"not-a-pcap",
                struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1),
            ):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    inspect_capture(path)
            write_capture(path, self.case["request"], self.case["response"])
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaises(ValueError):
                inspect_capture(path)
            with self.assertRaises(ValueError):
                write_capture(path, "", "", 11)

    def test_chunk_framing(self):
        self.assertEqual(dechunk(b"3\r\nabc\r\n0\r\n\r\n"), b"abc")
        for data in (b"garbage", b"3\r\nx", b"0\r\nTrailer: value\r\n\r\n"):
            with self.assertRaises(ValueError):
                dechunk(data)

    def test_native_schema_and_cli_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            cases = [copy.deepcopy(self.case)]
            cases[0]["expected"]["suricata"] = ["unknown"]
            path.write_text(json.dumps(cases))
            with self.assertRaises(ValueError):
                load_cases(path, "suricata", ["2026100"])
            path.write_text(json.dumps([self.case] * 2))
            with self.assertRaises(ValueError):
                load_cases(path, "suricata", ["2026100"])
            self.assertEqual(main(["--pcap", str(path), "--engine", "sigma"]), 2)
            self.assertEqual(main(["--fixtures", str(path)]), 2)

    def test_php_images_require_official_digests(self):
        with self.assertRaises(ValueError):
            run_matrix({"8.2": "example.invalid/php:latest"})

    def test_advisory_version_boundaries(self):
        for minor, fixed in (("8.2", 35), ("8.3", 36), ("8.4", 27), ("8.5", 12)):
            self.assertEqual(
                advisory_status(minor + "." + str(fixed - 1)), "below_advisory_fix"
            )
            self.assertEqual(
                advisory_status(minor + "." + str(fixed)), "at_or_above_advisory_fix"
            )
            self.assertEqual(
                advisory_status(minor + "." + str(fixed + 1)),
                "at_or_above_advisory_fix",
            )
        for unknown in ("8.6.0", "8.2.35-dev", "8.2", "invalid"):
            self.assertEqual(advisory_status(unknown), "unknown")


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.fixture = {"id": "sample", "expected": ["1"], "malicious": True}
        engine = engine_report("sigma", "test", ["1"], [(self.fixture, [])])
        self.report = {
            "schema_version": 1,
            "backend": "native",
            "passed": False,
            "engines": [engine],
            "crs": None,
        }

    def test_false_negative_and_sarif_locations(self):
        engine = self.report["engines"][0]
        self.assertEqual(engine["traffic"]["fn"], 1)
        self.assertEqual(engine["rules"]["1"]["fn"], 1)
        self.assertFalse(engine["passed"])
        result = sarif(self.report)["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "sigma/1")
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "tests/fixtures/native/sigma.json",
        )
        self.assertIn("missing 1", markdown(self.report))

    def test_unknown_alert_and_false_positive(self):
        with self.assertRaises(ValueError):
            engine_report("sigma", "test", ["1"], [(self.fixture, ["unknown"])])
        item = dict(self.fixture, expected=[], malicious=False)
        report = engine_report("sigma", "test", ["1"], [(item, ["1"])])
        self.assertEqual(report["traffic"]["fp"], 1)
        self.assertEqual(report["rules"]["1"]["fp"], 1)
        self.assertFalse(report["passed"])

    def test_reports_are_deterministic_and_html_is_escaped(self):
        self.report["engines"][0]["version"] = "<script>alert(1)</script>"
        with tempfile.TemporaryDirectory() as directory:
            write_reports(self.report, directory)
            first = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
            write_reports(self.report, directory)
            self.assertEqual(
                first, {p.name: p.read_bytes() for p in Path(directory).iterdir()}
            )
            self.assertIn(b"&lt;script&gt;", first["native.html"])
            self.assertNotIn(b"<script>", first["native.html"])

    @unittest.skipUnless(HAS_JSONSCHEMA, "Requires requirements-validation.txt")
    def test_sarif_schema_pass_and_failure_reports(self):
        import jsonschema

        schema = json.loads((ROOT / "tests/schemas/sarif-2.1.0.json").read_text())
        for report in (self.report, dict(self.report, passed=True, engines=[])):
            jsonschema.Draft4Validator(schema).validate(sarif(report))


@unittest.skipUnless(HAS_SIGMA, "Requires requirements-validation.txt")
class SigmaTests(unittest.TestCase):
    def test_real_conversion_and_event_evaluation(self):
        report = run_suite(["sigma"])
        self.assertTrue(report["passed"])
        self.assertEqual(report["engines"][0]["coverage_ratio"], 1)
        self.assertEqual(report["engines"][0]["traffic"]["fp"], 0)
        self.assertEqual(report["engines"][0]["traffic"]["fn"], 0)


@unittest.skipUnless(
    os.environ.get("P2S_NATIVE") == "1",
    "Run inside the native Docker image with P2S_NATIVE=1",
)
class EngineIntegrationTests(unittest.TestCase):
    def test_all_native_engines_and_crs(self):
        report = run_suite(["suricata", "modsecurity", "sigma"], with_crs=True)
        self.assertTrue(report["passed"], json.dumps(report, indent=2))
        self.assertTrue(report["crs"]["passed"])
        self.assertEqual([e["coverage_ratio"] for e in report["engines"]], [1, 1, 1])
        # Legitimate upload progress deliberately collides with broad signatures.
        self.assertEqual(report["engines"][0]["traffic"]["fp"], 1)
        self.assertEqual(report["engines"][1]["traffic"]["fp"], 1)
        # ModSecurity has no rules for LFI paths, long cookies, or exposed versions.
        self.assertEqual(report["engines"][1]["traffic"]["fn"], 4)
        self.assertEqual(report["engines"][0]["traffic"]["fn"], 0)

    def test_pcap_analysis_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.pcap"
            case = load_fixtures(ROOT / "tests/fixtures/native/http.json")[0]
            write_capture(path, case["request"], case["response"])
            self.assertEqual(main(["--pcap", str(path), "--output-dir", directory]), 0)
            report = json.loads((Path(directory) / "pcap.json").read_text())
            self.assertIn("2026100", report["rule_ids"])
            self.assertIsNone(report["metrics"])
