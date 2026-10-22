"""Schema, metrics, indicator limitations, and CLI regression tests."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import validate_detection as runner

ROOT = Path(__file__).resolve().parents[1]


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = runner.load_fixtures(runner.DEFAULT_FIXTURES)

    def test_default_corpus(self):
        with patch('socket.socket', side_effect=AssertionError('Network forbidden')):
            report = runner.build_report(self.fixtures)
        self.assertTrue(report['passed'])
        self.assertEqual(report['traffic']['tp'], 6)
        self.assertEqual(report['traffic']['tn'], 6)
        self.assertEqual(report['coverage_ratio'], 1)
        self.assertTrue(all(v == 'not_run' for v in report['native_engines'].values()))
        self.assertEqual(sum(runner.validate(self.fixtures)['upload_progress'].values()), 12)

    def test_every_signal_has_positive_and_negative(self):
        report = runner.build_report(self.fixtures)
        for signal in runner.INDICATORS:
            with self.subTest(signal=signal):
                self.assertGreater(report['signals'][signal]['tp'], 0)
                self.assertGreater(report['signals'][signal]['tn'], 0)

    def test_false_positive_and_false_negative(self):
        # A legitimate documentation request can contain a suspicious marker.
        benign = copy.deepcopy(self.fixtures[0])
        benign['id'] = 'benign-doc-example'
        benign['malicious'] = False
        benign['expected'] = dict.fromkeys(runner.INDICATORS, False)
        # URL encoding is outside the substring backend's capabilities.
        missed = copy.deepcopy(self.fixtures[3])
        missed['id'] = 'encoded-session-path'
        missed['request'] = missed['request'].replace('/sess_', '/%73ess_')
        report = runner.build_report(self.fixtures + [benign, missed])
        self.assertFalse(report['passed'])
        self.assertEqual(report['signals']['upload_progress']['fp'], 1)
        self.assertEqual(report['signals']['session_path']['fn'], 1)
        self.assertEqual(report['traffic']['fp'], 1)
        self.assertEqual(report['traffic']['fn'], 1)
        self.assertAlmostEqual(report['traffic']['precision'], 6 / 7)
        self.assertAlmostEqual(report['traffic']['recall'], 6 / 7)
        self.assertAlmostEqual(report['traffic']['false_positive_rate'], 1 / 7)
        self.assertIn('benign-doc-example', runner.render_markdown(report))

    def test_independent_traffic_labels(self):
        item = copy.deepcopy(self.fixtures[0])
        item['malicious'] = False
        report = runner.build_report([item])
        self.assertEqual(report['signals']['upload_progress']['fp'], 0)
        self.assertEqual(report['traffic']['fp'], 1)
        self.assertFalse(report['passed'])

    def test_undefined_metrics_and_incomplete_coverage(self):
        report = runner.build_report([self.fixtures[6]])
        self.assertIsNone(report['traffic']['precision'])
        self.assertIsNone(report['traffic']['recall'])
        self.assertEqual(report['traffic']['false_positive_rate'], 0)
        self.assertEqual(report['coverage_ratio'], 0)

    def test_schema_failures(self):
        mutations = [
            lambda x: x.update(id='bad|id'),
            lambda x: x.update(description=''),
            lambda x: x.update(request=42),
            lambda x: x.update(malicious=1),
            lambda x: x.update(extra=True),
            lambda x: x.pop('expected'),
            lambda x: x['expected'].pop('session_path'),
            lambda x: x['expected'].update(unknown=False),
            lambda x: x['expected'].update(upload_progress=1),
            lambda x: x.update(request='not HTTP\r\n\r\n'),
            lambda x: x.update(request='GET / HTTP/1.1\r\nbad-header\r\n\r\n'),
            lambda x: x.update(request='GET / HTTP/1.1'),
            lambda x: x.update(request='GET / HTTP/1.1\r\n\r\n' + 'x' * runner.MAX_REQUEST_BYTES),
        ]
        for mutation in mutations:
            item = copy.deepcopy(self.fixtures[0])
            mutation(item)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                runner.build_report([item])
        for invalid in ([], {}, None, [None], [self.fixtures[0]] * 2):
            with self.subTest(invalid=type(invalid)), self.assertRaises(ValueError):
                runner.build_report(invalid)

    def test_reports_are_deterministic_and_do_not_include_requests(self):
        first = runner.build_report(self.fixtures)
        self.assertEqual(first, runner.build_report(self.fixtures))
        self.assertEqual(runner.render_markdown(first), runner.render_markdown(first))
        self.assertNotIn('Host:', json.dumps(first))
        self.assertNotIn('Content-Disposition', runner.render_markdown(first))

    def test_duplicate_json_keys_and_file_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            path.write_text('[{"id":"one","id":"two"}]')
            with self.assertRaisesRegex(ValueError, 'Duplicate JSON key'):
                runner.load_fixtures(path)
            path.write_bytes(b' ' * (runner.MAX_FILE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, 'exceeds'):
                runner.load_fixtures(path)

    def cli(self, *args):
        return subprocess.run([sys.executable, '-B', str(ROOT / 'tools/validate_detection.py'), *args],
                              cwd=tempfile.gettempdir(), capture_output=True, text=True,
                              timeout=10, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))

    def test_cli_default_and_markdown(self):
        result = self.cli('--require-coverage')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['fixture_count'], 12)
        self.assertEqual(result.stdout, self.cli('--require-coverage').stdout)
        markdown = self.cli('--format', 'markdown')
        self.assertEqual(markdown.returncode, 0, markdown.stderr)
        self.assertIn('Native engines: **not run**', markdown.stdout)

    def test_cli_input_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixtures.json'
            result = self.cli('--fixtures', str(path))
            self.assertEqual(result.returncode, 2)
            for data in (b'{broken', b'[]', b'\xff', b'[' * 2000):
                path.write_bytes(data)
                result = self.cli('--fixtures', str(path))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn('Traceback', result.stderr)
            path.write_text(json.dumps(self.fixtures))
            self.assertEqual(self.cli('--fixtures', str(path), '--output', str(path)).returncode, 2)
            self.assertEqual(json.loads(path.read_text()), self.fixtures)

    def test_cli_regression_coverage_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixtures.json'
            output = Path(directory) / 'report.json'
            path.write_text(json.dumps([self.fixtures[6]]))
            self.assertEqual(self.cli('--fixtures', str(path)).returncode, 0)
            result = self.cli('--fixtures', str(path), '--require-coverage', '--output', str(output))
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse(json.loads(output.read_text())['passed'])
            item = copy.deepcopy(self.fixtures[0])
            item['expected']['upload_progress'] = False
            path.write_text(json.dumps([item]))
            self.assertEqual(self.cli('--fixtures', str(path)).returncode, 1)
            path.write_text(json.dumps(self.fixtures))
            self.assertEqual(self.cli('--fixtures', str(path), '--output', str(output)).returncode, 0)
            self.assertTrue(json.loads(output.read_text())['passed'])


if __name__ == '__main__':
    unittest.main()
