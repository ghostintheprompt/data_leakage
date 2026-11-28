"""Automated tests for data_leakage: offline CTI auditor (stdlib) + optional Flask server tests."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent / "lab"
if str(LAB_DIR) not in sys.path:
    sys.path.insert(0, str(LAB_DIR))

import offline_cti_auditor as auditor  # noqa: E402


HAS_FLASK = importlib.util.find_spec("flask") is not None


class TestOfflineCTIAuditor(unittest.TestCase):
    def test_detects_tokens_paths_and_keywords_in_leaking_har_and_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            har_path = tmp_path / "leaking.har"
            bundle_dir = tmp_path / "dist"
            bundle_dir.mkdir()
            report_path = tmp_path / "report.md"

            har_payload = {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "url": "https://sink.local/api/v1/rum?dd-api-key=pub_placeholder_token_abc123xyz789",
                                "postData": {
                                    "text": '{"route":"/workflows/flow_alpha","tag":"orchestrator"}'
                                },
                            }
                        }
                    ]
                }
            }
            har_path.write_text(json.dumps(har_payload), encoding="utf-8")
            (bundle_dir / "app.js").write_text(
                'const cfg = { env: "stealth", key: "pub_placeholder_token_abc123xyz789" };',
                encoding="utf-8",
            )

            har_finds = auditor.scan_har_file(str(har_path))
            bundle_finds = auditor.scan_bundle_dir(str(bundle_dir))
            auditor.render_cti_report("TestProject", har_finds, bundle_finds, str(report_path))

            self.assertIn("pub_placeholder_token_abc123xyz789", har_finds["tokens"])
            self.assertEqual(len(har_finds["paths"]), 1)
            self.assertIn("stealth", {k.lower() for k in bundle_finds["keywords"]})
            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("outside authorization perimeters", report_text)

    def test_clean_har_and_bundle_pass_without_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            har_path = tmp_path / "clean.har"
            bundle_dir = tmp_path / "dist"
            bundle_dir.mkdir()
            report_path = tmp_path / "report.md"

            har_payload = {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "url": "https://app.local/api/telemetry",
                                "postData": {"text": '{"service":"enterprise-app-prod"}'},
                            }
                        }
                    ]
                }
            }
            har_path.write_text(json.dumps(har_payload), encoding="utf-8")
            (bundle_dir / "app.js").write_text('console.log("enterprise-app-prod");', encoding="utf-8")

            har_finds = auditor.scan_har_file(str(har_path))
            bundle_finds = auditor.scan_bundle_dir(str(bundle_dir))
            auditor.render_cti_report("CleanProject", har_finds, bundle_finds, str(report_path))

            self.assertEqual(har_finds["tokens"], set())
            self.assertEqual(har_finds["paths"], set())
            self.assertEqual(bundle_finds["keywords"], set())
            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("Verification success", report_text)


@unittest.skipUnless(HAS_FLASK, "Flask not installed in host Python (run `make docker-test` for server tests)")
class TestFlaskTelemetrySink(unittest.TestCase):
    def test_cti_indicator_analyzer_flags_leaks(self) -> None:
        import telemetry_sink  # noqa: E402

        res = telemetry_sink.analyze_cti_indicators(
            endpoint="/api/rum",
            query_params={"dd-api-key": "pub_placeholder_token_abc123xyz789"},
            headers={"X-Campaign-Id": "camp_stealth_alpha"},
            payload={"resource": {"duration_ms": 1800, "tokens_used": 3500}, "detail": "system_prompt"},
        )
        types = {ind["type"] for ind in res["indicators"]}
        self.assertIn("QUERY_PARAM_TOKEN_LOG_LEAK", types)
        self.assertIn("PROJECT_METADATA_LEAK", types)
        self.assertIn("AGENT_LATENCY_FINGERPRINT", types)
        self.assertIn("ERROR_BOUNDARY_PROMPT_TOOL_LEAK", types)


if __name__ == "__main__":
    unittest.main(verbosity=2)
