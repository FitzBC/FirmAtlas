from pathlib import Path
import copy
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import tempfile
import threading
import unittest

from firmatlas.mapping import (
    DiscoveryCatalogRepository,
    MappingReasoningRunStatus,
    MappingReasoningRunStore,
    MappingReasoningService,
    MiniMaxReasonerAdapter,
    MiniMaxReasonerConfig,
)
from tests.test_mapping_catalog_repository import _catalog


class InlineExecutor:
    def submit(self, function, *args):
        function(*args)


class FakeReasoner:
    adapter_id = "fake-reasoner/v1"

    def __init__(self):
        self.requests = []

    def propose(self, request):
        self.requests.append(request)
        candidate_id = request.allowed_target_refs[0]
        evidence_id = request.allowed_evidence_ids[0]
        return {
            "proposals": [
                {
                    "kind": "analysis_step",
                    "target_ref": candidate_id,
                    "summary": "Trace the registrar call sites for this route.",
                    "rationale": "The cited frontend request has no verified handler owner.",
                    "cited_evidence_ids": [evidence_id],
                    "required_corroboration": "deterministic registrar or call-site evidence",
                    "confidence": 0.87,
                },
                {
                    "kind": "candidate_relation",
                    "target_ref": "invented:handler",
                    "summary": "Bind an invented handler.",
                    "rationale": "Unsupported model guess.",
                    "cited_evidence_ids": ["invented:evidence"],
                    "required_corroboration": "none",
                    "confidence": 0.99,
                },
            ],
            "usage": {"prompt_tokens": 120, "completion_tokens": 45},
        }


class FailOnceReasoner(FakeReasoner):
    def propose(self, request):
        if not self.requests:
            self.requests.append(request)
            raise RuntimeError("temporary provider failure")
        return super().propose(request)


class MappingReasoningServiceContractTests(unittest.TestCase):
    def test_failed_reasoning_run_can_be_retried_without_overwriting_attempt_one(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "firmatlas.db")
            mappings = DiscoveryCatalogRepository(database)
            catalog = _catalog()
            mappings.publish(catalog)
            service = MappingReasoningService(
                mappings, MappingReasoningRunStore(database), FailOnceReasoner(),
                executor=InlineExecutor(),
            )

            first = service.submit(catalog.catalog_id)
            second = service.submit(catalog.catalog_id)

            self.assertEqual(MappingReasoningRunStatus.FAILED, first.status)
            self.assertEqual(1, first.attempt)
            self.assertEqual(MappingReasoningRunStatus.PARTIAL, second.status)
            self.assertEqual(2, second.attempt)
            self.assertNotEqual(first.run_id, second.run_id)
            self.assertEqual(first.run_id, service.get(first.run_id).run_id)
            service.close()
            mappings.close()

    def test_reasoning_bundle_redacts_credentials_before_the_adapter_seam(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "firmatlas.db")
            mappings = DiscoveryCatalogRepository(database)
            document = copy.deepcopy(_catalog().to_dict())
            document["catalog_id"] = "discovery-catalog:" + "9" * 64
            document["evidence_atoms"][0]["object_value"] = "password=supersecret"
            mappings.publish_dict(document)
            reasoner = FakeReasoner()
            service = MappingReasoningService(
                mappings, MappingReasoningRunStore(database), reasoner,
                executor=InlineExecutor(),
            )

            service.submit(document["catalog_id"])
            serialized = json.dumps(reasoner.requests[0].to_dict())

            self.assertNotIn("supersecret", serialized)
            self.assertIn("<redacted:credential>", serialized)
            service.close()
            mappings.close()

    def test_minimax_retries_transient_http_errors_but_never_echoes_error_body(self):
        attempts = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                attempts.append(self.path)
                self.rfile.read(int(self.headers["Content-Length"]))
                if len(attempts) == 1:
                    body = b'{"error":"secret-key must never escape"}'
                    self.send_response(429)
                else:
                    body = json.dumps({
                        "choices": [{"finish_reason": "stop", "message": {
                            "content": '{"proposals":[]}',
                        }}],
                        "base_resp": {"status_code": 0},
                    }).encode()
                    self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            adapter = MiniMaxReasonerAdapter(MiniMaxReasonerConfig(
                base_url="http://127.0.0.1:{}/v1".format(server.server_port),
                api_key="secret-key", model="MiniMax-Test",
                max_attempts=2, retry_backoff_seconds=0,
            ))
            result = adapter.propose(type("Request", (), {
                "to_dict": lambda self: {"catalog_id": "catalog:test"}
            })())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(2, len(attempts))
        self.assertEqual([], result["proposals"])

    def test_minimax_adapter_uses_chat_completions_and_masks_its_key(self):
        captured = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                captured["path"] = self.path
                captured["authorization"] = self.headers["Authorization"]
                captured["body"] = json.loads(self.rfile.read(length))
                payload = json.dumps({
                    "id": "minimax-request-1", "model": "MiniMax-Test-Actual",
                    "choices": [{"finish_reason": "stop", "message": {
                        "content": json.dumps({"proposals": []}),
                    }}],
                    "usage": {"prompt_tokens": 23, "completion_tokens": 7},
                    "base_resp": {"status_code": 0, "status_msg": "success"},
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = MiniMaxReasonerConfig(
                base_url="http://127.0.0.1:{}/v1".format(server.server_port),
                api_key="secret-key",
                model="MiniMax-Test",
            )
            adapter = MiniMaxReasonerAdapter(config)
            result = adapter.propose(type("Request", (), {
                "to_dict": lambda self: {
                    "catalog_id": "catalog:test", "candidate_context": [],
                    "obligation_context": [], "evidence_context": [],
                }
            })())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual("/v1/chat/completions", captured["path"])
        self.assertEqual("Bearer secret-key", captured["authorization"])
        self.assertEqual("MiniMax-Test", captured["body"]["model"])
        self.assertNotIn("response_format", captured["body"])
        self.assertEqual(1800, captured["body"]["max_completion_tokens"])
        self.assertFalse(captured["body"]["stream"])
        self.assertEqual(23, result["usage"]["prompt_tokens"])
        self.assertEqual("MiniMax-Test-Actual", result["_provider"]["model"])
        self.assertEqual("minimax-request-1", result["_provider"]["request_id"])
        self.assertTrue(config.public_dict()["has_api_key"])
        self.assertNotIn("api_key", config.public_dict())

    def test_model_output_is_filtered_to_catalog_whitelists_and_stays_a_proposal(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "firmatlas.db")
            mappings = DiscoveryCatalogRepository(database)
            catalog = _catalog()
            mappings.publish(catalog)
            reasoner = FakeReasoner()
            store = MappingReasoningRunStore(database)
            service = MappingReasoningService(
                mappings, store, reasoner, executor=InlineExecutor(),
            )

            submitted = service.submit(catalog.catalog_id)
            observed = service.get(submitted.run_id)
            unchanged_catalog = mappings.get_catalog(catalog.catalog_id)

            self.assertEqual(MappingReasoningRunStatus.PARTIAL, observed.status)
            self.assertEqual(1, len(observed.proposals))
            proposal = observed.proposals[0]
            self.assertEqual(catalog.candidates[0].candidate_id, proposal.target_ref)
            self.assertEqual(catalog.evidence_atoms[0].evidence_id, proposal.cited_evidence_ids[0])
            self.assertEqual("model_suggested", proposal.status)
            self.assertEqual(1, observed.rejected_proposal_count)
            self.assertEqual(120, observed.prompt_tokens)
            self.assertEqual(len(catalog.evidence_atoms), len(unchanged_catalog["evidence_atoms"]))
            self.assertNotIn("reasoning_proposals", unchanged_catalog)

            service.close()
            mappings.close()


if __name__ == "__main__":
    unittest.main()
