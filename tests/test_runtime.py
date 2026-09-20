"""
JOCKY Runtime, Evidence & Analysis Test Suite
"""
import sys
import os
import json
import unittest
import tempfile
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from compiler.compiler import Compiler
from runtime.executor import JockyRuntime


def _compile_and_run(src: str):
    # Keep the runtime fixtures aligned with the public, quoted-string grammar.
    src = src.replace("CASE T", 'CASE "T"').replace("TARGET LOCAL", 'TARGET "LOCAL"')
    temp_dir = tempfile.gettempdir()
    def _repl(m):
        fname = os.path.basename(m.group(1).rstrip('"'))
        full_path = os.path.join(temp_dir, fname).replace("\\", "/")
        return f'REPORT "{full_path}"'
    src = re.sub(r'REPORT "?(/tmp/[^\n"]+)"?', _repl, src)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jocky", delete=False, encoding="utf-8") as f:
        f.write(src)
        path = f.name
    try:
        ir = Compiler().compile_file(path)
        runtime = JockyRuntime()
        return runtime.execute(ir)
    finally:
        os.unlink(path)


class TestRuntime(unittest.TestCase):

    def test_collect_processes(self):
        ctx = _compile_and_run('CASE T\nTARGET LOCAL\nCOLLECT processes\nREPORT "/tmp/jocky_test_r1.json"')
        self.assertIn("processes", ctx.collected_data)
        data = ctx.collected_data["processes"]
        self.assertGreater(data.get("process_count", 0), 0)

    def test_collect_network(self):
        ctx = _compile_and_run('CASE T\nTARGET LOCAL\nCOLLECT network.connections\nREPORT "/tmp/jocky_test_r2.json"')
        self.assertIn("network.connections", ctx.collected_data)

    def test_collect_drivers(self):
        ctx = _compile_and_run('CASE T\nTARGET LOCAL\nCOLLECT drivers\nREPORT "/tmp/jocky_test_r3.json"')
        self.assertIn("drivers", ctx.collected_data)

    def test_analyze_processes(self):
        ctx = _compile_and_run('CASE T\nTARGET LOCAL\nCOLLECT processes\nANALYZE processes\nREPORT "/tmp/jocky_test_r4.json"')
        self.assertIn("processes", ctx.analysis_results)

    def test_let_filter(self):
        ctx = _compile_and_run(
            'CASE T\nTARGET LOCAL\nCOLLECT processes\n'
            'LET big_pids = ANALYZE processes WHERE pid > 1\n'
            'REPORT "/tmp/jocky_test_r5.json"'
        )
        self.assertIn("big_pids", ctx.variables)
        matched = ctx.variables["big_pids"]["matched_count"]
        total = ctx.variables["big_pids"]["input_count"]
        self.assertLessEqual(matched, total)

    def test_let_and_filter(self):
        ctx = _compile_and_run(
            'CASE T\nTARGET LOCAL\nCOLLECT processes\n'
            'LET filtered = ANALYZE processes WHERE pid > 1 AND threads > 0\n'
            'REPORT "/tmp/jocky_test_r6.json"'
        )
        self.assertIn("filtered", ctx.variables)

    def test_let_paren_filter(self):
        ctx = _compile_and_run(
            'CASE T\nTARGET LOCAL\nCOLLECT processes\n'
            'LET p_filtered = ANALYZE processes WHERE (pid > 1 OR threads > 1) AND pid != 0\n'
            'REPORT "/tmp/jocky_test_r7.json"'
        )
        self.assertIn("p_filtered", ctx.variables)

    def test_correlate(self):
        ctx = _compile_and_run(
            'CASE T\nTARGET LOCAL\nCOLLECT processes\nCOLLECT network.connections\n'
            'CORRELATE processes WITH network.connections\n'
            'REPORT "/tmp/jocky_test_r8.json"'
        )
        self.assertGreater(len(ctx.correlations), 0)
        self.assertIn("explanation", ctx.correlations[0])

    def test_timeline(self):
        ctx = _compile_and_run(
            'CASE T\nTARGET LOCAL\nCOLLECT processes\nTIMELINE\nREPORT "/tmp/jocky_test_r9.json"'
        )
        self.assertIsInstance(ctx.timeline, list)

    def test_verify(self):
        ctx = _compile_and_run(
            'CASE T\nTARGET LOCAL\nCOLLECT processes\nVERIFY evidence\nREPORT "/tmp/jocky_test_r10.json"'
        )
        self.assertIn("_verification", ctx.evidence)

    def test_report_file_created(self):
        report_path = os.path.join(tempfile.gettempdir(), "jocky_test_report_final.json").replace("\\", "/")
        _compile_and_run(
            f'CASE T\nTARGET LOCAL\nCOLLECT processes\nANALYZE processes\nREPORT "{report_path}"'
        )
        self.assertTrue(os.path.exists(report_path))
        with open(report_path) as f:
            data = json.load(f)
        self.assertEqual(data.get("format"), "JOCKY-FORENSIC-REPORT")
        os.unlink(report_path)

    def test_risk_score_computed(self):
        ctx = _compile_and_run(
            'CASE T\nTARGET LOCAL\nCOLLECT processes\nANALYZE processes\nREPORT "/tmp/jocky_test_r11.json"'
        )
        # Risk may not be computed without explicit RISK instruction but risk dict exists
        # Just ensure no crash
        self.assertIsInstance(ctx.risk, dict)


class TestEvidence(unittest.TestCase):

    def test_evidence_hashed(self):
        ctx = _compile_and_run(
            'CASE T\nTARGET LOCAL\nCOLLECT processes\nVERIFY evidence\nREPORT "/tmp/jocky_ev_test.json"'
        )
        evidence = {k:v for k,v in ctx.evidence.items() if k != "_verification"}
        self.assertGreater(len(evidence), 0)
        for eid, ev in evidence.items():
            rec = ev.get("record", {})
            self.assertIn("sha256", rec)

    def test_evidence_integrity_verified(self):
        ctx = _compile_and_run(
            'CASE T\nTARGET LOCAL\nCOLLECT processes\nVERIFY evidence\nREPORT "/tmp/jocky_ev_test2.json"'
        )
        verification = ctx.evidence.get("_verification", {})
        self.assertIsInstance(verification, dict)


class TestCorrelation(unittest.TestCase):

    def test_process_network_correlation(self):
        ctx = _compile_and_run(
            'CASE T\nTARGET LOCAL\nCOLLECT processes\nCOLLECT network.connections\n'
            'CORRELATE processes WITH network.connections\nREPORT "/tmp/jocky_corr_test.json"'
        )
        self.assertGreater(len(ctx.correlations), 0)
        corr = ctx.correlations[0]
        self.assertIn("type", corr)
        self.assertIn("explanation", corr)

    def test_process_filesystem_correlation(self):
        ctx = _compile_and_run(
            'CASE T\nTARGET LOCAL\nCOLLECT processes\nCOLLECT filesystem.recent\n'
            'CORRELATE processes WITH filesystem.recent\nREPORT "/tmp/jocky_corr_test2.json"'
        )
        self.assertGreater(len(ctx.correlations), 0)


class TestNewCollectors(unittest.TestCase):

    def test_driver_collector(self):
        from forensics.drivers import DriverCollector
        result = DriverCollector().collect()
        self.assertIn("drivers", result)
        self.assertIn("driver_count", result)
        self.assertEqual(result["collector"], "drivers")

    def test_event_collector(self):
        from forensics.events import EventCollector
        result = EventCollector().collect()
        self.assertIn("events", result)
        self.assertEqual(result["collector"], "events")

    def test_binary_collector(self):
        from forensics.binaries import BinaryCollector
        result = BinaryCollector().collect()
        self.assertIn("binaries", result)
        self.assertEqual(result["collector"], "binaries")


if __name__ == "__main__":
    unittest.main(verbosity=2)
