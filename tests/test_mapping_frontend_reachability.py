import hashlib
import json
from pathlib import Path
import unittest
from dataclasses import replace

from firmatlas.mapping import (
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryCandidateKind,
    DiscoveryProducerBatch,
    FrontendInvocationStatus,
    SourceArtifactEntry,
    discover_frontend_invocation_reachability,
    discover_frontend_requests,
    assemble_discovery_catalog,
)


def _source(content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        "webroot_ro/js/dlna.js",
        "webroot_ro/js/dlna.js",
        "file",
        len(content),
        hashlib.sha256(content).hexdigest(),
    )


class FrontendInvocationReachabilityContractTests(unittest.TestCase):
    def test_commented_event_binding_does_not_make_request_function_reachable(self):
        content = b'''function refreshDLNA() {
  $.post("/goform/refreshDLNA", "action=1", callback);
}
function initEvent() {
  // $("#refresh").on("click", refreshDLNA);
}
initEvent();'''
        source = _source(content)
        frontend = discover_frontend_requests(source, content)

        result = discover_frontend_invocation_reachability(
            source, content, frontend
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.invocations))
        invocation = result.invocations[0]
        self.assertEqual(
            FrontendInvocationStatus.DECLARED_BUT_UNREACHED,
            invocation.status,
        )
        self.assertEqual("refreshDLNA", invocation.function_name)
        self.assertEqual(1, invocation.commented_reference_count)
        self.assertEqual((), invocation.call_path)
        self.assertEqual(
            {
                "classifies_frontend_invocation",
                "observes_commented_function_reference",
                "constructs_request",
            },
            {item.capability for item in result.evidence_atoms},
        )

    def test_top_level_direct_call_makes_request_function_reachable(self):
        content = b'''function sendRequest() {
  $.post("/goform/Send", "value=1", callback);
}
sendRequest();'''
        source = _source(content)
        frontend = discover_frontend_requests(source, content)

        result = discover_frontend_invocation_reachability(
            source, content, frontend
        )

        invocation = result.invocations[0]
        self.assertEqual(
            FrontendInvocationStatus.ACTIVE_CALL_PATH, invocation.status
        )
        self.assertEqual("top_level_direct_call", invocation.root_kind)
        self.assertEqual(("sendRequest",), invocation.call_path)
        self.assertIn(
            "establishes_frontend_call_edge",
            {item.capability for item in result.evidence_atoms},
        )

    def test_framework_callback_and_event_delegate_propagate_reachability(self):
        content = b'''var view = R.moduleView({initEvent: initEvent});
function initEvent() {
  $("#folder").delegate(".entry", "click", function () {
    getMoreFolder();
  });
}
function getMoreFolder() {
  $.GetSetData.setData("goform/expandDlnaFile?", {}, callback);
}'''
        source = _source(content)
        frontend = discover_frontend_requests(source, content)

        result = discover_frontend_invocation_reachability(
            source, content, frontend
        )

        invocation = result.invocations[0]
        self.assertEqual(
            FrontendInvocationStatus.ACTIVE_CALL_PATH, invocation.status
        )
        self.assertEqual("framework_registered_callback", invocation.root_kind)
        self.assertEqual(("initEvent", "getMoreFolder"), invocation.call_path)

    def test_top_level_request_declaration_is_not_called_unreachable(self):
        content = b'''var pageModel = R.pageModel({
  getUrl: "goform/GetDlnaCfg"
});'''
        source = _source(content)
        frontend = discover_frontend_requests(source, content)

        result = discover_frontend_invocation_reachability(
            source, content, frontend
        )

        invocation = result.invocations[0]
        self.assertEqual(
            FrontendInvocationStatus.TOP_LEVEL_DECLARATION,
            invocation.status,
        )
        self.assertIsNone(invocation.function_name)
        self.assertEqual("top_level_declaration", invocation.root_kind)

    def test_method_call_with_same_name_does_not_invoke_local_function(self):
        content = b'''function post() {
  $.post("/goform/LocalOnly", "value=1", callback);
}
$.post("/goform/TopLevel", "value=2", callback);'''
        source = _source(content)
        frontend = discover_frontend_requests(source, content)

        result = discover_frontend_invocation_reachability(
            source, content, frontend
        )

        by_endpoint = {item.endpoint: item for item in result.invocations}
        self.assertEqual(
            FrontendInvocationStatus.DECLARED_BUT_UNREACHED,
            by_endpoint["/goform/LocalOnly"].status,
        )
        self.assertEqual(
            FrontendInvocationStatus.TOP_LEVEL_DECLARATION,
            by_endpoint["/goform/TopLevel"].status,
        )

    def test_assigned_function_expression_keeps_its_invocation_identity(self):
        content = b'''var refresh = function () {
  $.post("/goform/Refresh", "action=1", callback);
};
// $("#refresh").on("click", refresh);'''
        source = _source(content)
        frontend = discover_frontend_requests(source, content)

        result = discover_frontend_invocation_reachability(
            source, content, frontend
        )

        invocation = result.invocations[0]
        self.assertEqual(
            FrontendInvocationStatus.DECLARED_BUT_UNREACHED,
            invocation.status,
        )
        self.assertEqual("refresh", invocation.function_name)
        self.assertEqual(1, invocation.commented_reference_count)

    def test_named_event_callback_is_an_active_static_root(self):
        content = b'''function sendRequest() {
  $.post("/goform/SendFromEvent", "value=1", callback);
}
$("#submit").on("click", sendRequest);'''
        source = _source(content)
        frontend = discover_frontend_requests(source, content)

        result = discover_frontend_invocation_reachability(
            source, content, frontend
        )

        invocation = result.invocations[0]
        self.assertEqual(
            FrontendInvocationStatus.ACTIVE_CALL_PATH, invocation.status
        )
        self.assertEqual("event_registered_callback", invocation.root_kind)
        self.assertEqual(("sendRequest",), invocation.call_path)

    def test_unregistered_anonymous_function_remains_unresolved(self):
        content = b'''var holder = {run: function () {
  $.post("/goform/Anonymous", "value=1", callback);
}};'''
        source = _source(content)
        frontend = discover_frontend_requests(source, content)

        result = discover_frontend_invocation_reachability(
            source, content, frontend
        )

        invocation = result.invocations[0]
        self.assertEqual(
            FrontendInvocationStatus.UNRESOLVED, invocation.status
        )
        self.assertIsNone(invocation.function_name)
        self.assertEqual((), invocation.call_path)

    def test_missing_request_span_is_partial_instead_of_empty_success(self):
        content = b'$.post("/goform/MissingSpan", "value=1", callback);'
        source = _source(content)
        frontend = discover_frontend_requests(source, content)
        incomplete = replace(frontend, evidence_atoms=())

        result = discover_frontend_invocation_reachability(
            source, content, incomplete
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual((), result.invocations)
        self.assertEqual(
            ["frontend_reachability.request_span_unavailable"],
            [item.code for item in result.diagnostics],
        )

    def test_duplicate_function_names_remain_unresolved(self):
        content = b'''function send() {
  $.post("/goform/First", "value=1", callback);
}
function send() {
  $.post("/goform/Second", "value=2", callback);
}
send();'''
        source = _source(content)
        frontend = discover_frontend_requests(source, content)

        result = discover_frontend_invocation_reachability(
            source, content, frontend
        )

        self.assertEqual(
            {FrontendInvocationStatus.UNRESOLVED},
            {item.status for item in result.invocations},
        )

    def test_reachability_is_queryable_with_request_reference(self):
        content = b'''function refreshDLNA() {
  $.post("/goform/refreshDLNA", "action=1", callback);
}'''
        source = _source(content)
        frontend = discover_frontend_requests(source, content)
        reachability = discover_frontend_invocation_reachability(
            source, content, frontend
        )

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            firmware_artifact_sha256="1" * 64,
            source_inventory_sha256="2" * 64,
            batches=(
                DiscoveryProducerBatch.frontend((frontend,), "frontend"),
                DiscoveryProducerBatch.frontend_reachability(
                    (reachability,), "frontend:reachability"
                ),
            ),
        ))

        candidate = next(
            item for item in catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.FRONTEND_INVOCATION
        )
        attributes = dict(candidate.attributes)
        self.assertEqual("supported", candidate.claim_status.value)
        self.assertEqual("declared_but_unreached", attributes["status"])
        self.assertEqual("refreshDLNA", attributes["function_name"])
        self.assertEqual([], json.loads(attributes["call_path"]))
        self.assertEqual("0", attributes["commented_reference_count"])
        self.assertEqual(
            frontend.candidates[0].candidate_id,
            attributes["request_candidate_ref"],
        )

    def test_real_ac9_dlna_page_preserves_three_distinct_invocation_shapes(self):
        path = Path(
            "../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/"
            "squashfs-root/webroot_ro/js/dlna.js"
        )
        if not path.exists():
            self.skipTest("local AC9 representative sample is unavailable")
        content = path.read_bytes()
        source = _source(content)
        frontend = discover_frontend_requests(source, content)

        result = discover_frontend_invocation_reachability(
            source, content, frontend
        )

        by_endpoint = {item.endpoint: item for item in result.invocations}
        self.assertEqual(
            {
                "/goform/refreshDLNA",
                "goform/GetDlnaCfg",
                "goform/SetDlnaCfg",
                "goform/expandDlnaFile?",
            },
            set(by_endpoint),
        )
        self.assertEqual(
            FrontendInvocationStatus.DECLARED_BUT_UNREACHED,
            by_endpoint["/goform/refreshDLNA"].status,
        )
        self.assertEqual(
            FrontendInvocationStatus.ACTIVE_CALL_PATH,
            by_endpoint["goform/expandDlnaFile?"].status,
        )
        self.assertEqual(
            ("initEvent", "getMoreFolder"),
            by_endpoint["goform/expandDlnaFile?"].call_path,
        )
        self.assertEqual(
            {FrontendInvocationStatus.TOP_LEVEL_DECLARATION},
            {
                by_endpoint[endpoint].status
                for endpoint in ("goform/GetDlnaCfg", "goform/SetDlnaCfg")
            },
        )


if __name__ == "__main__":
    unittest.main()
