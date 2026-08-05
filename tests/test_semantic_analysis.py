import unittest
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from firmatlas.intelligence.models import RelevancePolicy, VulnerabilityRecord
from firmatlas.intelligence.relevance import FirmwareRelevanceClassifier
from firmatlas.intelligence.repository import IntelligenceRepository
from firmatlas.intelligence.semantic import (
    OpenAICompatibleSemanticAnalyzer,
    RuleSemanticAnalyzer,
    SemanticModelSettings,
)
from firmatlas.intelligence.semantic_service import SemanticAnalysisService


class RuleSemanticAnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.analyzer = RuleSemanticAnalyzer()

    def test_extracts_web_interface_parameter_and_attack_semantics(self) -> None:
        result = self.analyzer.analyze_text(
            "CVE-2024-0921",
            "D-Link DIR-816 A2",
            "Affected is an unknown functionality of the file "
            "/goform/setDeviceSettings of the component Web Interface. "
            "The manipulation of the argument statuscheckpppoeuser leads to "
            "os command injection. The attack can be launched remotely.",
        )

        self.assertEqual("/goform/setDeviceSettings", result.interfaces[0].value)
        self.assertEqual("http_route", result.interfaces[0].kind)
        self.assertEqual("Web Interface", result.interfaces[0].component)
        self.assertEqual("statuscheckpppoeuser", result.parameters[0].name)
        self.assertEqual("/goform/setDeviceSettings", result.parameters[0].interface)
        self.assertEqual("os command injection", result.parameters[0].security_effect)
        self.assertTrue(result.remotely_exploitable)

    def test_extracts_cgi_route_and_get_parameter(self) -> None:
        result = self.analyzer.analyze_text(
            "CVE-2024-3273",
            "D-Link NAS sharing",
            "Affected is an unknown function of the file /cgi-bin/nas_sharing.cgi "
            "of the component HTTP GET Request Handler. The manipulation of the "
            "argument system leads to command injection.",
        )

        self.assertEqual("/cgi-bin/nas_sharing.cgi", result.interfaces[0].value)
        self.assertEqual("GET", result.interfaces[0].method)
        self.assertEqual("system", result.parameters[0].name)
        self.assertEqual("query", result.parameters[0].location)

    def test_does_not_misclassify_reference_urls_as_firmware_interfaces(self) -> None:
        result = self.analyzer.analyze_text(
            "CVE-TEST", "Device API",
            "See https://example.com/security/advisory. The endpoint /api/run "
            "accepts the parameter cmd.",
        )

        self.assertEqual(["/api/run"], [item.value for item in result.interfaces])

    def test_filters_stack_trace_tags_file_targets_and_parameter_prose(self) -> None:
        result = self.analyzer.analyze_text(
            "CVE-TEST", "Kernel and traversal report",
            "Call Trace: <TASK> worker </TASK>. A traversal reads /etc/shadow. "
            "The unpacked file /squashfs-root/www/HNAP1/control.php is writable. "
            "The parameter to configure the system is not named. The component is a "
            "POST Parameter Handler and lacks parameter validation. The HTTP endpoint "
            "/goform/apply accepts the argument system.",
        )

        self.assertEqual(["/goform/apply"], [item.value for item in result.interfaces])
        self.assertEqual(["system"], [item.name for item in result.parameters])

    def test_does_not_treat_bare_network_ports_as_exposed_interfaces(self) -> None:
        result = self.analyzer.analyze_text(
            "CVE-PORT", "Embedded management daemon",
            "The remote management service listens on TCP port 8080 and is "
            "reachable without authentication.",
        )

        self.assertEqual((), result.interfaces)


class SemanticAnalysisServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = IntelligenceRepository(":memory:")
        record = VulnerabilityRecord(
            identifier="CVE-2024-0921",
            source="test",
            source_identifier="CVE-2024-0921",
            title="D-Link DIR-816 A2",
            summary="The file /goform/setDeviceSettings accepts the argument "
            "statuscheckpppoeuser and leads to os command injection.",
            published_at=None,
            modified_at="2024-01-01T00:00:00Z",
            vendor="D-Link",
            product="DIR-816 A2 firmware",
        )
        decision = FirmwareRelevanceClassifier().classify(record, RelevancePolicy())
        self.repository.upsert(record, decision)

    def tearDown(self) -> None:
        self.repository.close()

    def test_same_content_and_analyzer_are_not_analyzed_twice(self) -> None:
        analyzer = CountingAnalyzer()
        service = SemanticAnalysisService(self.repository, rule_analyzer=analyzer)

        first = service.analyze_identifier("CVE-2024-0921")
        second = service.analyze_identifier("CVE-2024-0921")

        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(1, analyzer.calls)
        self.assertEqual(1, service.overview()["analyzed"])

    def test_model_configuration_is_masked_and_part_of_cache_fingerprint(self) -> None:
        llm = FakeLlmAnalyzer()
        service = SemanticAnalysisService(
            self.repository, rule_analyzer=CountingAnalyzer(), llm_analyzer=llm
        )
        public = service.update_settings(
            {
                "enabled": True,
                "base_url": "http://127.0.0.1:48760/v1",
                "model": "local-model-a",
                "api_key": "top-secret",
            }
        )

        first = service.analyze_identifier("CVE-2024-0921")
        second = service.analyze_identifier("CVE-2024-0921")
        service.update_settings({"model": "local-model-b"})
        third = service.analyze_identifier("CVE-2024-0921")

        self.assertNotIn("api_key", public)
        self.assertTrue(public["has_api_key"])
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertFalse(third["cached"])
        self.assertEqual(2, llm.calls)
        self.assertEqual(42, first["prompt_tokens"])

    def test_batch_records_progress_and_skips_every_cached_vulnerability(self) -> None:
        extra = VulnerabilityRecord(
            identifier="CVE-2024-3273", source="test",
            source_identifier="CVE-2024-3273", title="D-Link NAS",
            summary="The file /cgi-bin/nas_sharing.cgi accepts the argument system.",
            published_at=None, modified_at=None, vendor="D-Link",
            product="DNS-320L firmware",
        )
        self.repository.upsert(
            extra, FirmwareRelevanceClassifier().classify(extra, RelevancePolicy())
        )
        analyzer = CountingAnalyzer()
        service = SemanticAnalysisService(self.repository, rule_analyzer=analyzer)

        first = service.run_batch()
        second = service.run_batch()

        self.assertEqual("succeeded", first["status"])
        self.assertEqual(2, first["analyzed_count"])
        self.assertEqual(0, first["cached_count"])
        self.assertEqual(0, second["analyzed_count"])
        self.assertEqual(2, second["cached_count"])
        self.assertEqual(2, analyzer.calls)

    def test_batch_is_rules_only_by_default_even_when_model_is_active(self) -> None:
        llm = FakeLlmAnalyzer()
        service = SemanticAnalysisService(self.repository, llm_analyzer=llm)
        service.update_settings(
            {
                "enabled": True,
                "base_url": "http://127.0.0.1:48760/v1",
                "model": "local-model",
                "api_key": "fixture-key",
            }
        )

        rules_job = service.run_batch()
        hybrid_job = service.run_batch(use_llm=True)

        self.assertEqual("rules", rules_job["strategy"])
        self.assertEqual("hybrid", hybrid_job["strategy"])
        self.assertEqual(1, llm.calls)
        self.assertEqual(1, hybrid_job["analyzed_count"])


class OpenAICompatibleSemanticAnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeModelHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_openai_compatible_adapter_tests_connection_and_validates_json(self) -> None:
        settings = SemanticModelSettings(
            enabled=True,
            base_url="http://127.0.0.1:{}/v1".format(self.server.server_port),
            model="fixture-model",
            api_key="fixture-key",
        )
        analyzer = OpenAICompatibleSemanticAnalyzer()
        rules = RuleSemanticAnalyzer().analyze_text("CVE-X", "Router", "No route given.")

        connection = analyzer.test_connection(settings)
        result = analyzer.enrich("CVE-X", "Router", "No route given.", rules, settings)

        self.assertEqual(["fixture-model"], connection["models"])
        self.assertEqual("/rpc/apply", result["interfaces"][0]["value"])
        self.assertEqual("llm", result["interfaces"][0]["source"])
        self.assertEqual(12, result["usage"]["prompt_tokens"])


class CountingAnalyzer(RuleSemanticAnalyzer):
    def __init__(self) -> None:
        self.calls = 0

    def analyze_text(self, identifier, title, description):
        self.calls += 1
        return super().analyze_text(identifier, title, description)


class FakeLlmAnalyzer:
    def __init__(self) -> None:
        self.calls = 0

    def enrich(self, identifier, title, description, rules, settings):
        self.calls += 1
        return {
            "interfaces": [
                {
                    "value": "/hidden/model-route",
                    "kind": "http_route",
                    "method": "POST",
                    "protocol": "HTTP",
                    "component": "Web Interface",
                    "confidence": 0.8,
                    "evidence": "model evidence",
                    "source": "llm",
                }
            ],
            "parameters": [],
            "attack_type": "command injection",
            "remotely_exploitable": True,
            "usage": {"prompt_tokens": 42, "completion_tokens": 17},
        }


class FakeModelHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._send({"data": [{"id": "fixture-model"}]})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        json.loads(self.rfile.read(length))
        content = json.dumps({
                    "interfaces": [{
                        "value": "/rpc/apply", "kind": "rpc", "method": "POST",
                        "protocol": "HTTP", "component": "management daemon",
                        "confidence": 0.82, "evidence": "RPC apply route",
                    }],
                    "parameters": [], "attack_type": None,
                    "remotely_exploitable": True,
                }) + "\n{\"diagnostic\":\"ignored trailing object\"}"
        self._send(
            {
                "choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 8},
            }
        )

    def _send(self, value):
        if self.headers.get("Authorization") != "Bearer fixture-key":
            self.send_response(401); self.end_headers(); return
        encoded = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    unittest.main()
